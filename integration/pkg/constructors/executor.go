package constructors

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client"
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
)

// NewExecutorCoordinator initializes the executor coordinator object.
func NewExecutorCoordinator(
	lggr logger.Logger,
	cfg executor.Configuration,
	// TODO: all these are EVM specific, shouldn't be.
	relayers map[protocol.ChainSelector]legacyevm.Chain,
	keys map[protocol.ChainSelector]keys.RoundRobin,
	fromAddresses map[protocol.ChainSelector][]common.Address,
) (*executor.Coordinator, error) {
	lggr.Infow("Executor configuration", "config", cfg)

	offRampAddresses := make(map[protocol.ChainSelector]protocol.UnknownAddress, len(cfg.ChainConfiguration))
	rmnAddresses := make(map[protocol.ChainSelector]protocol.UnknownAddress, len(cfg.ChainConfiguration))
	execPool := make(map[protocol.ChainSelector][]string, len(cfg.ChainConfiguration))
	execIntervals := make(map[protocol.ChainSelector]time.Duration, len(cfg.ChainConfiguration))
	defaultExecutorAddresses := make(map[protocol.ChainSelector]protocol.UnknownAddress, len(cfg.ChainConfiguration))

	for selStr, chainConfig := range cfg.ChainConfiguration {
		intSel, err := strconv.ParseUint(selStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse selector '%s': %w", selStr, err)
		}
		sel := protocol.ChainSelector(intSel)
		offRampAddresses[sel], err = protocol.NewUnknownAddressFromHex(chainConfig.OffRampAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to parse offramp address '%s': %w", chainConfig.OffRampAddress, err)
		}
		rmnAddresses[sel], err = protocol.NewUnknownAddressFromHex(chainConfig.RmnAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to parse rmn address '%s': %w", chainConfig.RmnAddress, err)
		}
		execPool[sel] = chainConfig.ExecutorPool
		execIntervals[sel] = chainConfig.ExecutionInterval
		defaultExecutorAddresses[sel], err = protocol.NewUnknownAddressFromHex(chainConfig.DefaultExecutorAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to parse default executor address '%s': %w", chainConfig.DefaultExecutorAddress, err)
		}
	}

	executorMonitoring, err := monitoring.InitMonitoring()
	if err != nil {
		lggr.Errorw("Failed to initialize executor monitoring", "error", err)
		return nil, fmt.Errorf("failed to initialize executor monitoring: %w", err)
	}

	transmitters := make(map[protocol.ChainSelector]chainaccess.ContractTransmitter)
	destReaders := make(map[protocol.ChainSelector]chainaccess.DestinationReader)
	rmnReaders := make(map[protocol.ChainSelector]chainaccess.RMNCurseReader)
	for sel, chain := range relayers {
		if _, ok := offRampAddresses[sel]; !ok {
			lggr.Warnw("No offramp configured for chain, skipping.", "chainID", sel)
			continue
		}

		transmitters[sel] = contracttransmitter.NewEVMContractTransmitterFromTxm(
			logger.With(lggr, "component", "ContractTransmitter"),
			sel,
			chain.TxManager(),
			common.HexToAddress(offRampAddresses[sel].String()),
			keys[sel],
			fromAddresses[sel],
		)

		evmDestReader, err := destinationreader.NewEvmDestinationReader(
			destinationreader.Params{
				Lggr:                      logger.With(lggr, "component", "DestinationReader"),
				ChainSelector:             sel,
				ChainClient:               chain.Client(),
				OfframpAddress:            offRampAddresses[sel].String(), // TODO: use UnknownAddress instead of string?
				RmnRemoteAddress:          rmnAddresses[sel].String(),
				CacheExpiry:               cfg.ReaderCacheExpiry,
				ExecutionVisabilityWindow: cfg.MaxRetryDuration,
				Monitoring:                executorMonitoring,
			})
		if err != nil {
			lggr.Errorw("Failed to create destination reader", "error", err, "chainSelector", sel)
			continue
		}

		destReaders[sel] = evmDestReader
		rmnReaders[sel] = evmDestReader
	}

	curseChecker := cursechecker.NewCachedCurseChecker(cursechecker.Params{
		Lggr:        lggr,
		RmnReaders:  rmnReaders,
		CacheExpiry: cfg.ReaderCacheExpiry,
	})

	// create indexer client which implements MessageReader and VerifierResultReader (supports multiple indexers)
	indexerClient, err := client.NewMultiIndexerClient(cfg.IndexerAddress, &http.Client{
		Timeout: 30 * time.Second,
	})
	if err != nil {
		lggr.Errorw("Failed to create indexer client", "error", err)
		return nil, fmt.Errorf("failed to create indexer client: %w", err)
	}
	indexerAdapter := executor.NewIndexerReaderAdapter(indexerClient, executorMonitoring)

	ex := x.NewChainlinkExecutor(
		logger.With(lggr, "component", "Executor"),
		transmitters,
		destReaders,
		curseChecker,
		indexerAdapter,
		executorMonitoring,
		defaultExecutorAddresses,
	)

	// create hash-based leader elector
	le := leaderelector.NewHashBasedLeaderElector(
		lggr,
		execPool,
		cfg.ExecutorID,
		execIntervals,
	)
	backoffProvider := timeprovider.NewBackoffNTPProvider(lggr, cfg.BackoffDuration, cfg.NtpServer)

	indexerStream := ccvstreamer.NewIndexerStorageStreamer(
		lggr,
		ccvstreamer.IndexerStorageConfig{
			IndexerClient:    indexerAdapter,
			InitialQueryTime: time.Now().Add(-1 * cfg.LookbackWindow),
			PollingInterval:  indexerPollingInterval,
			Backoff:          cfg.BackoffDuration,
			QueryLimit:       cfg.IndexerQueryLimit,
			ExpiryDuration:   messageContextWindow,
			CleanInterval:    indexerGarbageCollectionInterval,
			TimeProvider:     backoffProvider,
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
