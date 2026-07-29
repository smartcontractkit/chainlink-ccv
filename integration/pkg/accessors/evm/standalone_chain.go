package evm

import (
	"context"
	"errors"
	"fmt"
	"sync"

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
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
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

	txm, err := txmgr.NewTxmV2(
		nil, // Forwarders are disabled, so TXM v2 does not use a DataSource.
		c.chainConfig.EVM(),
		txmgr.NewEvmTxmFeeConfig(c.chainConfig.EVM().GasEstimator()),
		c.chainConfig.EVM().Transactions(),
		c.chainConfig.EVM().Transactions().TransactionManagerV2(),
		c.chainClient,
		logger.Named(c.lggr, "Txm"),
		logpoller.LogPollerDisabled,
		chainKeystore,
		estimator,
		c.chainConfig.EVM().GasEstimator(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create production EVM transaction manager: %w", err)
	}
	if err := txm.Start(ctx); err != nil {
		_ = txm.Close()
		return nil, fmt.Errorf("failed to start production EVM transaction manager: %w", err)
	}

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
