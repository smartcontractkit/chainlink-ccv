package constructors

import (
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/destinationreader"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"

	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
)

// NewExecutorCoordinator initializes the executor coordinator object.
func NewExecutorCoordinator(
	lggr logger.Logger,
	cfg executor.Configuration,
	// no executor secrets?
	//ccvSecrets CCVSecretsConfig,
	relayers map[protocol.ChainSelector]legacyevm.Chain,
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
			chain.TxManager())

		destReaders[sel] = destinationreader.NewEvmDestinationReader(
			logger.With(lggr, "component", "DestinationReader"),
			sel,
			chain.Client(),
			offRampAddresses[sel].String(), // TODO: use UnknownAddress instead of string?
			cfg.GetCCVInfoCacheExpiry())
	}

	var monitoring executor.Monitoring // TODO: implement monitoring

	// create indexer client which implements MessageReader and VerifierResultReader
	indexerClient := storageaccess.NewIndexerAPIReader(lggr, cfg.IndexerAddress)

	ex := x.NewChainlinkExecutor(
		logger.With(lggr, "component", "Executor"),
		transmitters,
		destReaders,
		indexerClient,
		monitoring)

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
			LastQueryTime:   time.Now().Add(-1 * cfg.GetLookbackWindow()).Unix(),
			PollingInterval: cfg.GetPollingInterval(),
			Backoff:         cfg.GetBackoffDuration(),
			QueryLimit:      cfg.IndexerQueryLimit,
		})

	exec, err := executor.NewCoordinator(
		executor.WithLogger(logger.With(lggr, "component", "Coordinator")),
		executor.WithExecutor(ex),
		executor.WithLeaderElector(le),
		executor.WithMessageSubscriber(indexerStream),
		executor.WithMonitoring(monitoring),
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
