package evm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/mailbox"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	evmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
	"github.com/smartcontractkit/chainlink-evm/pkg/gas"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	evmkeys "github.com/smartcontractkit/chainlink-evm/pkg/keys"
	evmkeysv2 "github.com/smartcontractkit/chainlink-evm/pkg/keys/v2"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"
)

// chainRuntime is the lifecycle boundary owned by one EVM accessor. Keeping it
// behind this narrow interface makes the accessor wiring testable without
// replacing chainlink-evm's production implementations.
type chainRuntime interface {
	ChainClient() (client.Client, error)
	HeadTracker() (heads.Tracker, error)
	NewContractTransmitter(
		ctx context.Context,
		chainSelector protocol.ChainSelector,
		ks keystore.Keystore,
		keyName string,
		offRampAddress common.Address,
	) (chainaccess.ContractTransmitter, error)
	Close() error
}

type standaloneChain struct {
	lggr            logger.Logger
	chainClient     client.Client
	chainConfig     *evmconfig.ChainScoped
	headBroadcaster heads.Broadcaster
	headTracker     heads.Tracker
	mailMonitor     *mailbox.Monitor

	mu                  sync.Mutex
	txm                 txmgr.TxManager
	unsubscribeTXM      func()
	contractTransmitter chainaccess.ContractTransmitter
	closed              bool

	// recoveryStop cancels the orphan recovery goroutine, which spends most of its life in a grace
	// period sleep and must not outlive the accessor. recoveryWG lets Close wait for it, so the
	// chain client is not torn down while recovery is still reading nonces through it.
	recoveryStop services.StopChan
	recoveryWG   sync.WaitGroup
}

func newStandaloneChain(ctx context.Context, info Info, lggr logger.Logger) (*standaloneChain, error) {
	chainClient, chainConfig, err := newMultiNodeClientFromInfo(info, lggr)
	if err != nil {
		return nil, err
	}

	headBroadcaster := heads.NewBroadcaster(lggr)
	mailMonitor := mailbox.NewMonitor("ccv-standalone-evm-"+info.ChainID, lggr)
	headSaver := heads.NewSaver(
		lggr,
		heads.NewNullORM(),
		chainConfig.EVM(),
		chainConfig.EVM().HeadTracker(),
	)
	headTracker := heads.NewTracker(
		lggr,
		chainClient,
		chainConfig.EVM(),
		chainConfig.EVM().HeadTracker(),
		headBroadcaster,
		headSaver,
		mailMonitor,
	)

	if err := chainClient.Dial(ctx); err != nil {
		chainClient.Close()
		return nil, fmt.Errorf("failed to dial production EVM client for chain %s: %w", info.ChainID, err)
	}

	var servicesToStart services.MultiStart
	// MultiStart rolls back every service it started, in reverse order, if a
	// later Start fails. The separately owned chain client is closed here.
	if err := servicesToStart.Start(ctx, mailMonitor, headBroadcaster, headTracker); err != nil {
		chainClient.Close()
		return nil, fmt.Errorf("failed to start production EVM head tracker for chain %s: %w", info.ChainID, err)
	}

	lggr.Infow("Started production EVM chain services",
		"chainID", info.ChainID,
		"headTracker", headTracker.Name(),
		"nodeCount", len(chainConfig.Nodes()),
	)
	return &standaloneChain{
		lggr:            lggr,
		chainClient:     chainClient,
		chainConfig:     chainConfig,
		headBroadcaster: headBroadcaster,
		headTracker:     headTracker,
		mailMonitor:     mailMonitor,
		recoveryStop:    make(services.StopChan),
	}, nil
}

func (c *standaloneChain) ChainClient() (client.Client, error) {
	if c == nil || c.chainClient == nil {
		return nil, errors.New("EVM chain client is not available")
	}
	return c.chainClient, nil
}

func (c *standaloneChain) HeadTracker() (heads.Tracker, error) {
	if c == nil || c.headTracker == nil {
		return nil, errors.New("EVM head tracker is not available")
	}
	return c.headTracker, nil
}

// NewContractTransmitter starts chainlink-evm's production TXM v2 and returns
// the existing TXM-backed CCV transmitter. TXM owns nonce tracking, fee
// estimation, retries, gas bumping, and multi-node writes.
func (c *standaloneChain) NewContractTransmitter(
	ctx context.Context,
	chainSelector protocol.ChainSelector,
	ks keystore.Keystore,
	keyName string,
	offRampAddress common.Address,
) (chainaccess.ContractTransmitter, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, errors.New("EVM chain runtime is closed")
	}
	if c.contractTransmitter != nil {
		return c.contractTransmitter, nil
	}
	if ks == nil {
		return nil, errors.New("EVM transaction manager requires a keystore")
	}
	if keyName == "" {
		return nil, errors.New("EVM transaction manager requires a transmitter key name")
	}
	if offRampAddress == (common.Address{}) {
		return nil, errors.New("EVM transaction manager requires an OffRamp address")
	}

	coreKeystore := evmkeysv2.NewTxKeyCoreKeystore(
		ks,
		evmkeysv2.WithAllowedKeyNames([]string{keyName}),
	)
	chainKeystore := evmkeys.NewChainStore(coreKeystore, c.chainConfig.EVM().ChainID())
	fromAddresses, err := chainKeystore.EnabledAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load EVM transmitter key %q: %w", keyName, err)
	}
	if len(fromAddresses) == 0 {
		return nil, fmt.Errorf("EVM transmitter key %q was not found", keyName)
	}

	estimator, err := gas.NewEstimator(
		logger.Named(c.lggr, "GasEstimator"),
		c.chainClient,
		c.chainConfig.EVM().ChainType(),
		c.chainConfig.EVM().ChainID(),
		c.chainConfig.EVM().GasEstimator(),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create EVM gas estimator: %w", err)
	}

	txm, err := newTxmV2(
		logger.Named(c.lggr, "Txm"),
		c.chainConfig.EVM(),
		c.chainClient,
		chainKeystore,
		estimator,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create production EVM transaction manager: %w", err)
	}
	if err := txm.Start(ctx); err != nil {
		_ = txm.Close()
		return nil, fmt.Errorf("failed to start production EVM transaction manager: %w", err)
	}

	// Start has registered the transmitter addresses with the store, so recovery can seed into it.
	// Runs in the background: it waits to see whether orphans clear on their own, and blocking the
	// accessor for that long would stall every other chain behind it.
	c.startOrphanRecovery(txm, fromAddresses)

	currentHead, unsubscribe := c.headBroadcaster.Subscribe(txm)
	if currentHead != nil {
		txm.OnNewLongestChain(ctx, currentHead)
	}
	transmitter := contracttransmitter.NewEVMContractTransmitterFromTxm(
		logger.With(c.lggr, "component", "ContractTransmitter"),
		chainSelector,
		txm,
		offRampAddress,
		chainKeystore,
		fromAddresses,
		monitoring.NewNoopExecutorMonitoring(),
	)
	c.txm = txm
	c.unsubscribeTXM = unsubscribe
	c.contractTransmitter = transmitter
	c.lggr.Infow("Started production EVM transaction manager",
		"chainSelector", chainSelector,
		"fromAddresses", fromAddresses,
	)
	return transmitter, nil
}

// startOrphanRecovery drives transactions left in the mempool by a previous run of this process to
// completion, so an address is never blocked indefinitely by work this process cannot see.
//
// TXM v2 keeps transaction state in memory, so a restart loses the record of anything in flight.
// The nonce is still safe, because TXM reads the pending nonce from the chain on start, and the
// message is still safe, because the executor re-drives it from on-chain state. What is lost is the
// rebroadcast and gas bump that would have carried an unmined transaction to confirmation. Until
// that transaction mines or the mempool evicts it, nothing behind its nonce can confirm.
//
// Recovery waits before acting. An orphan that is merely slow will mine on its own, and replacing it
// would throw away a real execution and force the executor to send another. Only once the nonce has
// failed to advance for orphanRecoveryGracePeriod does this seed a replacement, by which point the
// transaction is stuck rather than slow.
func (c *standaloneChain) startOrphanRecovery(txm *txmV2, fromAddresses []common.Address) {
	c.recoveryWG.Go(func() {
		ctx, cancel := c.recoveryStop.NewCtx()
		defer cancel()
		for _, address := range fromAddresses {
			c.recoverOrphanedTransactions(ctx, txm, address)
		}
	})
}

func (c *standaloneChain) recoverOrphanedTransactions(ctx context.Context, txm *txmV2, address common.Address) {
	latest, pending, err := orphanedNonces(ctx, c.chainClient, address)
	if err != nil {
		c.lggr.Warnw("Could not check for orphaned transactions", "address", address, "error", err)
		return
	}
	if len(nonceRange(latest, pending)) == 0 {
		return
	}

	c.lggr.Warnw("Found transactions in flight from a previous run; waiting to see whether they confirm",
		"address", address,
		"count", pending-latest,
		"latestNonce", latest,
		"pendingNonce", pending,
		"grace", orphanRecoveryGracePeriod,
	)

	select {
	case <-ctx.Done():
		return
	case <-time.After(orphanRecoveryGracePeriod):
	}

	// Re-read rather than trusting the earlier snapshot: the orphans may have mined during the
	// grace period, and only what is still outstanding needs replacing.
	latest, pending, err = orphanedNonces(ctx, c.chainClient, address)
	if err != nil {
		c.lggr.Warnw("Could not re-check orphaned transactions after grace period", "address", address, "error", err)
		return
	}
	orphans := nonceRange(latest, pending)
	if len(orphans) == 0 {
		c.lggr.Infow("Orphaned transactions confirmed on their own; no recovery needed", "address", address)
		return
	}

	c.lggr.Warnw("Orphaned transactions did not confirm; seeding replacements to unblock the address",
		"address", address, "count", len(orphans), "latestNonce", latest, "pendingNonce", pending)
	for _, nonce := range orphans {
		if err := txm.seedOrphanedNonce(ctx, address, nonce); err != nil {
			// A nonce the TXM has already claimed for its own work needs no replacement, and that is
			// the common reason this fails. Log and continue so one nonce does not stop the rest.
			c.lggr.Warnw("Could not seed replacement for orphaned nonce",
				"address", address, "nonce", nonce, "error", err)
			continue
		}
		c.lggr.Infow("Seeded replacement for orphaned nonce", "address", address, "nonce", nonce)
	}
}

// Close stops event sources before their consumers, matching chainlink-evm's
// production chain lifecycle and preventing late head delivery during shutdown.
func (c *standaloneChain) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	headTracker := c.headTracker
	headBroadcaster := c.headBroadcaster
	mailMonitor := c.mailMonitor
	txm := c.txm
	unsubscribeTXM := c.unsubscribeTXM
	chainClient := c.chainClient
	c.mu.Unlock()

	// Stop orphan recovery first and wait for it. It reads nonces through the chain client and
	// writes to the TXM store, so both have to outlive it; abandoning it here would leave it calling
	// into a closed client.
	//
	// The wait is bounded. Closing recoveryStop cancels the context every nonce read derives from,
	// so a read in flight returns at once, the grace-period sleep selects on the same context, and
	// seeding only touches the in-memory store. Even with a chain client that ignored cancellation,
	// orphanRecoveryRPCTimeout caps each read.
	if c.recoveryStop != nil {
		close(c.recoveryStop)
	}
	c.recoveryWG.Wait()

	var err error
	if headTracker != nil {
		err = errors.Join(err, headTracker.Close())
	}
	if unsubscribeTXM != nil {
		unsubscribeTXM()
	}
	if headBroadcaster != nil {
		err = errors.Join(err, headBroadcaster.Close())
	}
	if txm != nil {
		err = errors.Join(err, txm.Close())
	}
	if mailMonitor != nil {
		err = errors.Join(err, mailMonitor.Close())
	}
	if chainClient != nil {
		chainClient.Close()
	}
	return err
}
