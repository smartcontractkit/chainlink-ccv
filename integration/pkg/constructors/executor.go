package constructors

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	adapter "github.com/smartcontractkit/chainlink-ccv/executor/pkg/adapter"
	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	timeprovider "github.com/smartcontractkit/chainlink-ccv/integration/pkg/backofftimeprovider"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/destinationreader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
	"github.com/smartcontractkit/chainlink-evm/pkg/keys"
)

var (
	indexerPollingInterval = 1 * time.Second
	// indexerGarbagecollectionInterval describes how frequently we garbage collect message duplicates from the indexer results
	// if this is too short, we will assume a message is net new every time it is read from the indexer.
	indexerGarbageCollectionInterval = 1 * time.Hour
	// messageContextWindow is the time window we use to expire duplicate messages from the indexer.
	// this combines with indexerGarbageCollectionInterval to avoid memory leak in the streamer.
	// We store messages for messageContextWindow, cleaning up old messages every indexerGarbageCollectionInterval.
	// These values should be set based on the indexer's message retry duration.
	messageContextWindow = 24 * time.Hour

	ntpBackoffDuration = 2 * time.Second
)

// NewExecutorCoordinator initializes the executor coordinator object.
func NewExecutorCoordinator(
	lggr logger.Logger,
	cfg executor.Configuration,
	chainAddresses chainaccess.GenericConfig,
	// TODO: all these are EVM specific, shouldn't be.
	relayers map[protocol.ChainSelector]legacyevm.Chain,
	keys map[protocol.ChainSelector]keys.RoundRobin,
	fromAddresses map[protocol.ChainSelector][]common.Address,
) (*executor.Coordinator, error) {
	if err := cfg.Validate(); err != nil {
		lggr.Errorw("Invalid executor configuration.", "error", err)
		return nil, fmt.Errorf("invalid executor configuration: %w", err)
	}

	lggr.Infow("Executor configuration", "config", cfg)

	execPool := make(map[protocol.ChainSelector][]string, len(cfg.ChainConfiguration))
	execIntervals := make(map[protocol.ChainSelector]time.Duration, len(cfg.ChainConfiguration))
	defaultExecutorAddresses := make(map[protocol.ChainSelector]protocol.UnknownAddress, len(cfg.ChainConfiguration))

	for selStr, chainConfig := range cfg.ChainConfiguration {
		intSel, err := strconv.ParseUint(selStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse selector '%s': %w", selStr, err)
		}
		sel := protocol.ChainSelector(intSel)
		execPool[sel] = chainConfig.ExecutorPool
		execIntervals[sel] = chainConfig.ExecutionInterval
		defaultExecutorAddresses[sel], err = protocol.NewUnknownAddressFromHex(chainConfig.DefaultExecutorAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to parse default executor address '%s': %w", chainConfig.DefaultExecutorAddress, err)
		}
	}

	protocol.InitChainSelectorCache()

	executorMonitoring, err := monitoring.InitMonitoring()
	if err != nil {
		lggr.Errorw("Failed to initialize executor monitoring", "error", err)
		return nil, fmt.Errorf("failed to initialize executor monitoring: %w", err)
	}

	transmitters := make(map[protocol.ChainSelector]chainaccess.ContractTransmitter)
	destReaders := make(map[protocol.ChainSelector]chainaccess.DestinationReader)
	rmnReaders := make(map[protocol.ChainSelector]chainaccess.RMNCurseReader)
	enabledDestChains := make([]protocol.ChainSelector, 0)
	for sel, chain := range relayers {
		offRampAddrStr := chainAddresses.OffRampAddresses[sel.String()]
		if offRampAddrStr == "" {
			lggr.Warnw("No offramp configured for chain, skipping.", "chainID", sel)
			continue
		}
		offRampAddr, err := protocol.NewUnknownAddressFromHex(offRampAddrStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse offramp address '%s': %w", offRampAddrStr, err)
		}
		rmnAddrStr := chainAddresses.RMNRemoteAddresses[sel.String()]

		transmitters[sel] = contracttransmitter.NewEVMContractTransmitterFromTxm(
			logger.With(lggr, "component", "ContractTransmitter"),
			sel,
			chain.TxManager(),
			common.HexToAddress(offRampAddr.String()),
			keys[sel],
			fromAddresses[sel],
			executorMonitoring,
		)

		evmDestReader, err := destinationreader.NewEvmDestinationReader(
			destinationreader.Params{
				Lggr:                      logger.With(lggr, "component", "DestinationReader"),
				ChainSelector:             sel,
				ChainClient:               chain.Client(),
				OfframpAddress:            offRampAddrStr,
				RmnRemoteAddress:          rmnAddrStr,
				ExecutionVisabilityWindow: cfg.MaxRetryDuration,
				Monitoring:                executorMonitoring,
			})
		if err != nil {
			lggr.Errorw("Failed to create destination reader", "error", err, "chainSelector", sel)
			delete(transmitters, sel)
			continue
		}

		destReaders[sel] = evmDestReader
		rmnReaders[sel] = evmDestReader
		enabledDestChains = append(enabledDestChains, sel)
	}

	curseChecker := cursechecker.NewCachedCurseChecker(cursechecker.Params{
		Lggr:        lggr,
		Metrics:     executorMonitoring.Metrics(),
		RmnReaders:  rmnReaders,
		CacheExpiry: cfg.ReaderCacheExpiry,
	})

	// create indexer adapter which queries multiple indexers concurrently
	httpClient := &http.Client{Timeout: 30 * time.Second}
	indexerAdapter, err := adapter.NewIndexerReaderAdapter(
		cfg.IndexerAddress,
		httpClient,
		executorMonitoring,
		lggr,
	)
	if err != nil {
		lggr.Errorw("Failed to create indexer adapter", "error", err)
		return nil, fmt.Errorf("failed to create indexer adapter: %w", err)
	}

	ex := x.NewChainlinkExecutor(
		logger.With(lggr, "component", "Executor"),
		transmitters,
		destReaders,
		curseChecker,
		indexerAdapter,
		executorMonitoring,
		defaultExecutorAddresses,
	)
	if err := ex.Validate(); err != nil {
		return nil, fmt.Errorf("executor validation failed: %w", err)
	}

	// create hash-based leader elector
	le, err := leaderelector.NewHashBasedLeaderElector(
		lggr,
		execPool,
		cfg.ExecutorID,
		execIntervals,
	)
	if err != nil {
		return nil, fmt.Errorf("leader elector: %w", err)
	}
	// ntp is an external service call with special rate limits, we use a different backoff duration for it.
	backoffProvider := timeprovider.NewBackoffNTPProvider(lggr, ntpBackoffDuration, cfg.NtpServer)

	indexerStream := ccvstreamer.NewIndexerStorageStreamer(
		lggr,
		ccvstreamer.IndexerStorageConfig{
			IndexerClient:     indexerAdapter,
			InitialQueryTime:  time.Now().Add(-1 * cfg.LookbackWindow),
			PollingInterval:   indexerPollingInterval,
			Backoff:           cfg.BackoffDuration,
			QueryLimit:        cfg.IndexerQueryLimit,
			ExpiryDuration:    messageContextWindow,
			CleanInterval:     indexerGarbageCollectionInterval,
			TimeProvider:      backoffProvider,
			EnabledDestChains: enabledDestChains,
		})

	exec, err := executor.NewCoordinator(
		logger.With(lggr, "component", "Coordinator"),
		ex,
		indexerStream,
		le,
		executorMonitoring,
		cfg.MaxRetryDuration,
		backoffProvider,
		cfg.WorkerCount,
	)
	if err != nil {
		lggr.Errorw("Failed to create execution coordinator.", "error", err)
		return nil, fmt.Errorf("failed to create coordinator: %w", err)
	}

	return exec, nil
}
