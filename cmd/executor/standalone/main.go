package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/grafana/pyroscope-go"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	cmdexecutor "github.com/smartcontractkit/chainlink-ccv/cmd/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	adapter "github.com/smartcontractkit/chainlink-ccv/executor/pkg/adapter"
	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	_ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/backofftimeprovider"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	configPathEnvVar = "EXECUTOR_CONFIG_PATH"
	// indexerPollingInterval describes how frequently we ask indexer for new messages.
	// This should be kept at 1s for consistent behavior across all executors.
	indexerPollingInterval = 1 * time.Second
	// indexerGarbageCollectionInterval describes how frequently we garbage collect message duplicates from the indexer results.
	// if this is too short, we will assume a message is net new every time it is read from the indexer.
	indexerGarbageCollectionInterval = 1 * time.Hour
	// messageContextWindow is the time window we use to expire duplicate messages from the indexer.
	// this combines with indexerGarbageCollectionInterval to avoid memory leak in the streamer.
	// We store messages for messageContextWindow, cleaning up old messages every indexerGarbageCollectionInterval.
	messageContextWindow = 9 * time.Hour
)

type executorFactory struct {
	bootstrap.ServiceFactory

	coordinator *executor.Coordinator
	profiler    *pyroscope.Profiler
	lggr        logger.Logger
}

func (f *executorFactory) Stop(_ context.Context) error {
	var err error
	if f.coordinator != nil {
		err = f.coordinator.Close()
	}
	if f.profiler != nil {
		_ = f.profiler.Stop()
	}
	return err
}

func (f *executorFactory) Start(ctx context.Context, spec bootstrap.JobSpec, deps bootstrap.ServiceDeps) error {
	var rawConfig executor.ConfigWithBlockchainInfo[any]
	if err := spec.GetAppConfig(&rawConfig); err != nil {
		return fmt.Errorf("failed to decode executor config: %w", err)
	}

	executorConfig, err := rawConfig.GetNormalizedConfig()
	if err != nil {
		return fmt.Errorf("failed to normalize executor config: %w", err)
	}

	f.lggr, err = logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	f.lggr = logger.Sugared(logger.Named(f.lggr, "executor"))

	f.profiler, err = cmdexecutor.StartPyroscope(f.lggr, executorConfig.PyroscopeURL, "executor")
	if err != nil {
		f.lggr.Errorw("Failed to start pyroscope", "error", err)
	}

	protocol.InitChainSelectorCache()

	f.lggr.Infow("Executor configuration", "config", executorConfig)

	executorMonitoring := cmdexecutor.SetupMonitoring(f.lggr, executorConfig.Monitoring)

	contractTransmitters := make(map[protocol.ChainSelector]chainaccess.ContractTransmitter)
	destReaders := make(map[protocol.ChainSelector]chainaccess.DestinationReader)
	rmnReaders := make(map[protocol.ChainSelector]chainaccess.RMNCurseReader)
	enabledDestChains := make([]protocol.ChainSelector, 0)

	for strSel := range executorConfig.ChainConfiguration {
		selectorUint, err := strconv.ParseUint(strSel, 10, 64)
		if err != nil {
			f.lggr.Errorw("Invalid chain selector in configuration", "error", err, "chainSelector", strSel)
			continue
		}
		selector := protocol.ChainSelector(selectorUint)

		accessor, err := deps.Registry.GetAccessor(ctx, selector)
		if err != nil {
			f.lggr.Errorw("Failed to get accessor for chain", "error", err, "chainSelector", strSel)
			continue
		}

		dr, drErr := accessor.DestinationReader()
		ct, ctErr := accessor.ContractTransmitter()

		if drErr != nil || ctErr != nil {
			f.lggr.Warnw("Skipping chain: missing DestinationReader or ContractTransmitter", "chainSelector", strSel, "destReaderErr", drErr, "transmitterErr", ctErr)
			continue
		}

		destReaders[selector] = dr
		rmnReaders[selector] = dr
		contractTransmitters[selector] = ct
		enabledDestChains = append(enabledDestChains, selector)
	}

	curseChecker := cursechecker.NewCachedCurseChecker(cursechecker.Params{
		Lggr:        f.lggr,
		Metrics:     executorMonitoring.Metrics(),
		RmnReaders:  rmnReaders,
		CacheExpiry: executorConfig.ReaderCacheExpiry,
	})

	httpClient := &http.Client{Timeout: 30 * time.Second}
	verifierResultReader, err := adapter.NewIndexerReaderAdapter(
		executorConfig.IndexerAddress,
		httpClient,
		executorMonitoring,
		f.lggr,
	)
	if err != nil {
		return fmt.Errorf("failed to create indexer adapter: %w", err)
	}

	execPool := make(map[protocol.ChainSelector][]string)
	execIntervals := make(map[protocol.ChainSelector]time.Duration)
	defaultExecutorAddresses := make(map[protocol.ChainSelector]protocol.UnknownAddress)

	for strSel, chainConfig := range executorConfig.ChainConfiguration {
		selectorUint, err := strconv.ParseUint(strSel, 10, 64)
		if err != nil {
			f.lggr.Errorw("Invalid chain selector in configuration", "error", err, "chainSelector", strSel)
			continue
		}
		sel := protocol.ChainSelector(selectorUint)
		execPool[sel] = chainConfig.ExecutorPool
		execIntervals[sel] = chainConfig.ExecutionInterval
		defaultExecutorAddresses[sel], err = protocol.NewUnknownAddressFromHex(chainConfig.DefaultExecutorAddress)
		if err != nil {
			f.lggr.Errorw("Invalid default executor address in configuration", "error", err, "chainSelector", strSel)
			continue
		}
	}

	ex := x.NewChainlinkExecutor(f.lggr, contractTransmitters, destReaders, curseChecker, verifierResultReader, executorMonitoring, defaultExecutorAddresses)
	if err := ex.Validate(); err != nil {
		return fmt.Errorf("failed to validate chainlink executor: %w", err)
	}

	le, err := leaderelector.NewHashBasedLeaderElector(
		f.lggr,
		execPool,
		executorConfig.ExecutorID,
		execIntervals,
	)
	if err != nil {
		return fmt.Errorf("failed to create leader elector: %w", err)
	}

	timeProvider := backofftimeprovider.NewBackoffNTPProvider(f.lggr, executorConfig.BackoffDuration, executorConfig.NtpServer)

	indexerStream := ccvstreamer.NewIndexerStorageStreamer(
		f.lggr,
		ccvstreamer.IndexerStorageConfig{
			IndexerClient:     verifierResultReader,
			InitialQueryTime:  time.Now().Add(-1 * executorConfig.LookbackWindow),
			PollingInterval:   indexerPollingInterval,
			Backoff:           executorConfig.BackoffDuration,
			QueryLimit:        executorConfig.IndexerQueryLimit,
			ExpiryDuration:    messageContextWindow,
			CleanInterval:     indexerGarbageCollectionInterval,
			TimeProvider:      timeProvider,
			EnabledDestChains: enabledDestChains,
		})

	f.coordinator, err = executor.NewCoordinator(
		f.lggr,
		ex,
		indexerStream,
		le,
		executorMonitoring,
		executorConfig.MaxRetryDuration,
		timeProvider,
		executorConfig.WorkerCount,
	)
	if err != nil {
		return fmt.Errorf("failed to create execution coordinator: %w", err)
	}

	if err := f.coordinator.Start(ctx); err != nil {
		return fmt.Errorf("failed to start execution coordinator: %w", err)
	}

	return nil
}

func main() {
	configPath := executor.DefaultConfigFile
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}
	if envConfig := os.Getenv(configPathEnvVar); envConfig != "" {
		configPath = envConfig
	}

	err := bootstrap.Run(
		"Executor",
		&executorFactory{},
		bootstrap.WithTOMLAppConfig(configPath),
	)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to run executor: %v\n", err)
		os.Exit(1)
	}
}
