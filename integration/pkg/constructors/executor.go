package constructors

import (
	"fmt"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	timeprovider "github.com/smartcontractkit/chainlink-ccv/integration/pkg/backofftimeprovider"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/destinationreader"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
	"github.com/smartcontractkit/chainlink-evm/pkg/keys"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
)

var (
	indexerPollingInterval = 1 * time.Second
	// indexerGarbagecollectionInterval describes how frequently we garbage collect message duplicates from the indexer results
	// if this is too short, we will assume a message is net new every time it is read from the indexer.
	indexerGarbageCollectionInterval = 24 * time.Hour
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

	transmitters := make(map[protocol.ChainSelector]executor.ContractTransmitter)
	destReaders := make(map[protocol.ChainSelector]executor.DestinationReader)
	rmnReaders := make(map[protocol.ChainSelector]ccvcommon.RMNRemoteReader)
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
				Lggr:             logger.With(lggr, "component", "DestinationReader"),
				ChainSelector:    sel,
				ChainClient:      chain.Client(),
				OfframpAddress:   offRampAddresses[sel].String(), // TODO: use UnknownAddress instead of string?
				RmnRemoteAddress: rmnAddresses[sel].String(),
				CacheExpiry:      cfg.ReaderCacheExpiry,
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

	// TODO: monitoring config home
	executorMonitoring, err := monitoring.InitMonitoring(beholder.Config{
		InsecureConnection:       cfg.Monitoring.Beholder.InsecureConnection,
		CACertFile:               cfg.Monitoring.Beholder.CACertFile,
		OtelExporterHTTPEndpoint: cfg.Monitoring.Beholder.OtelExporterHTTPEndpoint,
		OtelExporterGRPCEndpoint: cfg.Monitoring.Beholder.OtelExporterGRPCEndpoint,
		LogStreamingEnabled:      cfg.Monitoring.Beholder.LogStreamingEnabled,
		MetricReaderInterval:     time.Second * time.Duration(cfg.Monitoring.Beholder.MetricReaderInterval),
		TraceSampleRatio:         cfg.Monitoring.Beholder.TraceSampleRatio,
		TraceBatchTimeout:        time.Second * time.Duration(cfg.Monitoring.Beholder.TraceBatchTimeout),
	})
	if err != nil {
		lggr.Errorw("Failed to initialize executor monitoring", "error", err)
		return nil, fmt.Errorf("failed to initialize executor monitoring: %w", err)
	}

	// create indexer client which implements MessageReader and VerifierResultReader
	indexerClient := storageaccess.NewIndexerAPIReader(lggr, cfg.IndexerAddress)

	ex := x.NewChainlinkExecutor(
		logger.With(lggr, "component", "Executor"),
		transmitters,
		destReaders,
		curseChecker,
		indexerClient,
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
			IndexerClient:    indexerClient,
			InitialQueryTime: time.Now().Add(-1 * cfg.LookbackWindow),
			PollingInterval:  indexerPollingInterval,
			Backoff:          cfg.BackoffDuration,
			QueryLimit:       cfg.IndexerQueryLimit,
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
