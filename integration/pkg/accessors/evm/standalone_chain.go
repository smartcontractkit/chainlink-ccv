package evm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/common/lazy"
	commonmonitoring "github.com/smartcontractkit/chainlink-ccv/common/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/mailbox"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	clevmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
	"github.com/smartcontractkit/chainlink-evm/pkg/gas"
	"github.com/smartcontractkit/chainlink-evm/pkg/gas/rollups"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	evmkeys "github.com/smartcontractkit/chainlink-evm/pkg/keys"
	evmkeysv2 "github.com/smartcontractkit/chainlink-evm/pkg/keys/v2"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"
)

const (
	// orphanRecoveryGracePeriod is how long a restarted process waits for
	// transactions left in flight by its predecessor to confirm on their own before
	// replacing them. A transaction that is merely slow mines within this window and
	// is left alone; replacing one needlessly discards a real execution and makes the
	// executor send another. See standaloneChain.recoverOrphanedTransactions.
	orphanRecoveryGracePeriod = 90 * time.Second
	// orphanRecoveryRPCTimeout bounds a single nonce read during orphan recovery. Recovery runs on a
	// goroutine Close waits for, so every network call it makes needs a deadline of its own rather
	// than relying on the RPC client having one.
	orphanRecoveryRPCTimeout = 30 * time.Second
)

// Node URL label keys for the chain plugin config beholder event. They match the keys the core
// node's EVM relayer uses for the same event (chainlink-evm/pkg/relay), so downstream consumers
// see identical labels from standalone services and core nodes.
const (
	nodeURLKeyHTTP = "HTTPURL"
	nodeURLKeyWS   = "WSURL"
)

// rawNodeURLs maps each configured RPC node to its endpoints for the chain plugin config
// beholder event. The emitter normalizes the URLs (scheme://host only) before emission.
func rawNodeURLs(nodes []Node) []map[string]string {
	rawNodes := make([]map[string]string, 0, len(nodes))
	for _, n := range nodes {
		nodeURLs := make(map[string]string)
		if httpURL := strings.TrimSpace(n.HTTPUrl); httpURL != "" {
			nodeURLs[nodeURLKeyHTTP] = httpURL
		}
		if wsURL := strings.TrimSpace(n.WSUrl); wsURL != "" {
			nodeURLs[nodeURLKeyWS] = wsURL
		}
		if len(nodeURLs) == 0 {
			continue
		}
		rawNodes = append(rawNodes, nodeURLs)
	}
	return rawNodes
}

// chainRuntime is the lifecycle boundary owned by one EVM accessor. Keeping it
// behind this narrow interface makes the accessor wiring testable without
// replacing chainlink-evm's production implementations.
type chainRuntime interface {
	ChainClient() (client.Client, error)
	HeadTracker() (heads.Tracker, error)
	// DAGasPriceOracle returns nil when the chain type has no data availability fee.
	DAGasPriceOracle(ctx context.Context) (rollups.L1Oracle, error)
	TransmitterAddresses(ctx context.Context, ks keystore.Keystore, keyName string) ([]common.Address, error)
	SourceReaderHeaderFetchBatchSize() int
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
	selector        protocol.ChainSelector
	chainClient     client.Client
	chainConfig     *clevmconfig.ChainScoped
	headBroadcaster heads.Broadcaster
	headTracker     heads.Tracker
	mailMonitor     *mailbox.Monitor
	// configEmitter emits the chain's ChainPluginConfig (CSA key + normalized RPC endpoints) to
	// Beholder, as a core node relayer does, so NOPs sharing RPC endpoints can be detected.
	configEmitter *commonmonitoring.ChainPluginConfigEmitter

	// txmBlockTime and txmBlockTimeSource are resolved from the operator's Info at construction
	// for the logging NewContractTransmitter emits: chainConfig carries the block time already
	// defaulted, which cannot be told apart from one the operator set.
	txmBlockTime       time.Duration
	txmBlockTimeSource evmconfig.TXMBlockTimeSource

	sourceReaderHeaderFetchBatchSize int

	mu                  sync.Mutex
	txm                 txmgr.TxManager
	daOracle            *lazy.Lazy[rollups.L1Oracle]
	unsubscribeTXM      func()
	contractTransmitter chainaccess.ContractTransmitter
	closed              bool

	// logPoller is built by the first LogPoller call, through newLogPoller.
	newLogPoller logPollerBuilder
	logPoller    logpoller.LogPoller

	// recoveryStop cancels the orphan recovery goroutine, which spends most of its life in a grace
	// period sleep and must not outlive the accessor. recoveryWG lets Close wait for it, so the
	// chain client is not torn down while recovery is still reading nonces through it.
	recoveryStop services.StopChan
	recoveryWG   sync.WaitGroup
}

func newStandaloneChain(ctx context.Context, selector protocol.ChainSelector, info Info, lggr logger.Logger) (*standaloneChain, error) {
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

	// The config emitter reports this chain's RPC endpoints to Beholder as a core node's EVM
	// relayer does; an empty CSA key falls back to the beholder client's auth key. With Beholder
	// disabled the global emitter is a no-op, so it runs unconditionally.
	configEmitter := commonmonitoring.NewChainPluginConfigEmitter(lggr, "", info.ChainID, rawNodeURLs(info.Nodes))

	var servicesToStart services.MultiStart
	// MultiStart rolls back every service it started, in reverse order, if a
	// later Start fails. The separately owned chain client is closed here.
	if err := servicesToStart.Start(ctx, mailMonitor, headBroadcaster, headTracker, configEmitter); err != nil {
		chainClient.Close()
		return nil, fmt.Errorf("failed to start production EVM head tracker for chain %s: %w", info.ChainID, err)
	}

	lggr.Infow("Started production EVM chain services",
		"chainID", info.ChainID,
		"headTracker", headTracker.Name(),
		"nodeCount", len(chainConfig.Nodes()),
	)
	txmBlockTime, txmBlockTimeSource := evmconfig.ResolveTXMBlockTime(info)
	chain := &standaloneChain{
		lggr:                             lggr,
		selector:                         selector,
		chainClient:                      chainClient,
		chainConfig:                      chainConfig,
		headBroadcaster:                  headBroadcaster,
		headTracker:                      headTracker,
		mailMonitor:                      mailMonitor,
		configEmitter:                    configEmitter,
		txmBlockTime:                     txmBlockTime,
		txmBlockTimeSource:               txmBlockTimeSource,
		sourceReaderHeaderFetchBatchSize: sourceReaderHeaderFetchBatchSize(info.SourceReaderHeaderFetchBatchSize),
		newLogPoller:                     buildLogPoller,
		recoveryStop:                     make(services.StopChan),
	}
	chain.daOracle = lazy.New(chain.buildDAGasPriceOracle)
	return chain, nil
}

// SourceReaderHeaderFetchBatchSize returns the configured source-reader header
// batch size, defaulted to DefaultSourceReaderHeaderFetchBatchSize.
func (c *standaloneChain) SourceReaderHeaderFetchBatchSize() int {
	return c.sourceReaderHeaderFetchBatchSize
}

// sourceReaderHeaderFetchBatchSize returns batchSize or
// DefaultSourceReaderHeaderFetchBatchSize when batchSize is not positive.
func sourceReaderHeaderFetchBatchSize(batchSize int) int {
	if batchSize <= 0 {
		return evmconfig.DefaultSourceReaderHeaderFetchBatchSize
	}
	return batchSize
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

// DAGasPriceOracle builds and starts the data availability gas price oracle on the first call.
// It returns nil for chain types that have no data availability fee.
func (c *standaloneChain) DAGasPriceOracle(ctx context.Context) (rollups.L1Oracle, error) {
	if c == nil || c.daOracle == nil {
		return nil, errors.New("EVM DA gas price oracle is not available")
	}
	return c.daOracle.Value(ctx)
}

// buildDAGasPriceOracle starts the oracle. The start waits for the first RPC read, so it holds no lock.
func (c *standaloneChain) buildDAGasPriceOracle(ctx context.Context) (rollups.L1Oracle, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, errors.New("EVM chain runtime is closed")
	}
	oracle, err := rollups.NewL1GasOracle(
		logger.Named(c.lggr, "DAGasPriceOracle"),
		c.chainClient,
		c.chainConfig.EVM().ChainType(),
		c.chainConfig.EVM().GasEstimator().DAOracle(),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create EVM DA gas price oracle: %w", err)
	}
	if oracle == nil {
		return nil, nil
	}
	if err := oracle.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start EVM DA gas price oracle: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.Join(errors.New("EVM chain runtime is closed"), oracle.Close())
	}
	return oracle, nil
}

// TransmitterAddresses returns the addresses of the enabled keys that have the given key name.
func (c *standaloneChain) TransmitterAddresses(ctx context.Context, ks keystore.Keystore, keyName string) ([]common.Address, error) {
	if ks == nil {
		return nil, errors.New("EVM transmitter addresses require a keystore")
	}
	coreKeystore := evmkeysv2.NewTxKeyCoreKeystore(ks, evmkeysv2.WithAllowedKeyNames([]string{keyName}))
	addresses, err := evmkeys.NewChainStore(coreKeystore, c.chainConfig.EVM().ChainID()).EnabledAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load EVM transmitter key %q: %w", keyName, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("EVM transmitter key %q was not found", keyName)
	}
	return addresses, nil
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

	switch c.txmBlockTimeSource {
	case evmconfig.TXMBlockTimeGenericFallback:
		// Warned here rather than when the chain is built: a source-only chain, the verifier's for
		// instance, never reaches this point and never runs a TXM, so the fallback does not apply to
		// it. Loud because this chain has no curated default and 2s is a far steeper retry and
		// fee-bump cadence than the node produced on a slow chain; set it explicitly per chain before
		// a cutover. The inspect-config migration tooling flags the same fact offline.
		c.lggr.Warnw("no txm_block_time configured for chain and no curated default exists; TXM v2 "+
			"falls back to a 2s block time (retry and fee-bump cadence). Set txm_block_time "+
			"(standalone config) or Transactions.TransactionManagerV2.BlockTime (node config) "+
			"explicitly per chain",
			"chainID", c.chainConfig.EVM().ChainID().String())
	case evmconfig.TXMBlockTimeCuratedDefault:
		// Not a warning: the curated value tracks the chain's real block interval, so the cadence
		// is right. Logged anyway so the source of the value is visible next to the TXM startup
		// lines. An explicit txm_block_time still overrides it.
		c.lggr.Infow("no txm_block_time configured for chain; using the curated per-chain default",
			"chainID", c.chainConfig.EVM().ChainID().String(),
			"blockTime", c.txmBlockTime.String())
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

var _ logPollerRuntime = (*standaloneChain)(nil)

// EVMChainID returns the chain's configured EVM chain ID.
func (c *standaloneChain) EVMChainID() *big.Int {
	return c.chainConfig.EVM().ChainID()
}

// LogPoller builds and starts this chain's LogPoller on the first call and returns the same one
// afterwards. The process-wide guard is taken before anything is built, so a second runtime for
// the same evm_chain_id fails instead of writing to the same rows.
func (c *standaloneChain) LogPoller(ctx context.Context, db *sql.DB) (logpoller.LogPoller, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, errors.New("EVM chain runtime is closed")
	}
	if c.logPoller != nil {
		return c.logPoller, nil
	}
	chainID := c.chainConfig.EVM().ChainID()
	if db == nil {
		return nil, fmt.Errorf("log poller for chain selector %d (evm_chain_id %s) requires the EVM database", c.selector, chainID)
	}

	if err := logPollerGuard.acquire(chainID.String(), c.selector); err != nil {
		return nil, err
	}

	// Building fails the same way on every attempt (metric registration), so the caller skips the chain.
	lp, err := c.newLogPoller(logPollerInputs{
		chainID:     chainID,
		logger:      logger.Named(c.lggr, "LogPoller"),
		client:      c.chainClient,
		headTracker: c.headTracker,
		config:      c.chainConfig.EVM(),
		db:          db,
	})
	if err != nil {
		logPollerGuard.release(chainID.String(), c.selector)
		return nil, fmt.Errorf("failed to build log poller for chain selector %d (evm_chain_id %s): %w", c.selector, chainID, err)
	}
	if err := lp.Start(ctx); err != nil {
		// Never started, so nothing can be writing and the chain may be released.
		logPollerGuard.release(chainID.String(), c.selector)
		return nil, fmt.Errorf("failed to start log poller for chain selector %d (evm_chain_id %s): %w", c.selector, chainID, err)
	}

	c.logPoller = lp
	return lp, nil
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
	configEmitter := c.configEmitter
	lp := c.logPoller
	c.mu.Unlock()

	// Stop the config emitter first: it is independent of the chain services and this stops
	// emissions as soon as shutdown begins (reverse of startup order).
	var err error
	if configEmitter != nil {
		err = errors.Join(err, configEmitter.Close())
	}

	// Stop orphan recovery next and wait for it. It reads nonces through the chain client and
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

	// The LogPoller reads heads from the head tracker, so it stops first. A poller something else
	// already stopped is not writing, so its chain is released. Any other failed close keeps the
	// chain held: the poller may still be writing, and a second poller must not start beside it.
	if lp != nil {
		chainID := c.chainConfig.EVM().ChainID().String()
		if closeErr := lp.Close(); closeErr != nil && !errors.Is(closeErr, services.ErrAlreadyStopped) {
			c.lggr.Errorw("Failed to close log poller, keeping its chain held",
				"chainSelector", c.selector, "evmChainID", chainID, "error", closeErr)
			err = errors.Join(err, fmt.Errorf("failed to close log poller for chain selector %d (evm_chain_id %s): %w", c.selector, chainID, closeErr))
		} else {
			logPollerGuard.release(chainID, c.selector)
		}
	}

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
	if c.daOracle != nil && c.daOracle.Derived() {
		// The oracle is derived, so Value returns the cached oracle without any call.
		if daOracle, _ := c.daOracle.Value(context.Background()); daOracle != nil {
			err = errors.Join(err, daOracle.Close())
		}
	}
	if mailMonitor != nil {
		err = errors.Join(err, mailMonitor.Close())
	}
	if chainClient != nil {
		chainClient.Close()
	}
	return err
}
