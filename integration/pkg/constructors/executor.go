package constructors

import (
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/destinationreader"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
	"github.com/smartcontractkit/chainlink-evm/pkg/keys"

	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
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
	offRampAddresses, err := mapAddresses(cfg.OffRampAddresses)
	if err != nil {
		lggr.Errorw("Invalid CCV configuration, failed to map offramp addresses.", "error", err)
		return nil, fmt.Errorf("invalid ccv configuration: failed to map offramp addresses: %w", err)
	}

	transmitters := make(map[protocol.ChainSelector]executor.ContractTransmitter)
	destReaders := make(map[protocol.ChainSelector]executor.DestinationReader)
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

		destReaders[sel] = destinationreader.NewEvmDestinationReader(
			logger.With(lggr, "component", "DestinationReader"),
			sel,
			chain.Client(),
			offRampAddresses[sel].String(), // TODO: use UnknownAddress instead of string?
			cfg.GetCCVInfoCacheExpiry())
	}

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
		indexerClient,
		executorMonitoring,
	)

	// create hash-based leader elector
	le := leaderelector.NewHashBasedLeaderElector(
		lggr,
		cfg.ExecutorPool,
		cfg.ExecutorID,
		cfg.GetExecutionInterval(),
		cfg.GetMinWaitPeriod(),
	)

	indexerStream := ccvstreamer.NewIndexerStorageStreamer(
		lggr,
		ccvstreamer.IndexerStorageConfig{
			IndexerClient:   indexerClient,
			LastQueryTime:   time.Now().Add(-1 * cfg.GetLookbackWindow()).UnixMilli(),
			PollingInterval: cfg.GetPollingInterval(),
			Backoff:         cfg.GetBackoffDuration(),
			QueryLimit:      cfg.IndexerQueryLimit,
		})

	exec, err := executor.NewCoordinator(
		logger.With(lggr, "component", "Coordinator"),
		ex,
		indexerStream,
		le,
		executorMonitoring,
	)
	if err != nil {
		lggr.Errorw("Failed to create execution coordinator.", "error", err)
		return nil, fmt.Errorf("failed to create coordinator: %w", err)
	}

	return exec, nil
	/*
		err = exec.Start(ctx)
		if err != nil {
			lggr.Errorw("Failed to start execution coordinator.", "error", err)
			return
		}

		for {
			lggr.Info("Executor is running:", exec.HealthReport())
			time.Sleep(10 * time.Second)
		}
	*/
}
