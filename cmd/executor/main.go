package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ethereum/go-ethereum/common"
	"github.com/grafana/pyroscope-go"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/destinationreader"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	executorcommon "github.com/smartcontractkit/chainlink-ccv/executor/pkg/common"
	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
)

const (
	CONFIG_PATH = "EXECUTOR_CONFIG_PATH"
	PK_ENV_VAR  = "EXECUTOR_TRANSMITTER_PRIVATE_KEY"
)

func main() {
	configPath, ok := os.LookupEnv(CONFIG_PATH)
	if !ok {
		configPath = "executor_config.toml"
	}
	executorConfig, err := loadConfiguration(configPath)
	if err != nil {
		os.Exit(1)
	}
	if err = executorConfig.Validate(); err != nil {
		os.Exit(1)
	}

	// Setup logging - always debug level for now
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	if err != nil {
		panic(err)
	}

	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "executor",
		ServerAddress:   executorConfig.PyroscopeURL,
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileBlockDuration,
			pyroscope.ProfileMutexDuration,
		},
	}); err != nil {
		lggr.Errorw("Failed to start pyroscope", "error", err)
	}

	// Use SugaredLogger for better API
	lggr = logger.Sugared(lggr)

	lggr.Infow("Executor configuration", "config", executorConfig)

	// Setup OTEL Monitoring (via beholder)
	var executorMonitoring executorcommon.ExecutorMonitoring
	if executorConfig.Monitoring.Enabled && executorConfig.Monitoring.Type == "beholder" {
		executorMonitoring, err = monitoring.InitMonitoring(beholder.Config{
			InsecureConnection:       executorConfig.Monitoring.Beholder.InsecureConnection,
			CACertFile:               executorConfig.Monitoring.Beholder.CACertFile,
			OtelExporterHTTPEndpoint: executorConfig.Monitoring.Beholder.OtelExporterHTTPEndpoint,
			OtelExporterGRPCEndpoint: executorConfig.Monitoring.Beholder.OtelExporterGRPCEndpoint,
			LogStreamingEnabled:      executorConfig.Monitoring.Beholder.LogStreamingEnabled,
			MetricReaderInterval:     time.Second * time.Duration(executorConfig.Monitoring.Beholder.MetricReaderInterval),
			TraceSampleRatio:         executorConfig.Monitoring.Beholder.TraceSampleRatio,
			TraceBatchTimeout:        time.Second * time.Duration(executorConfig.Monitoring.Beholder.TraceBatchTimeout),
		})
		if err != nil {
			lggr.Fatalf("Failed to initialize indexer monitoring: %v", err)
		}
	} else {
		lggr.Info("Using noop monitoring")
		executorMonitoring = monitoring.NewNoopExecutorMonitoring()
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	contractTransmitters := make(map[protocol.ChainSelector]executor.ContractTransmitter)
	destReaders := make(map[protocol.ChainSelector]executor.DestinationReader)
	// create executor components
	for strSel, chain := range executorConfig.BlockchainInfos {
		selector, err := strconv.ParseUint(strSel, 10, 64)
		if err != nil {
			lggr.Errorw("Invalid chain selector in configuration", "error", err, "chainSelector", strSel)
			continue
		}

		chainClient := pkg.CreateMultiNodeClientFromInfo(ctx, chain, lggr)
		dr := destinationreader.NewEvmDestinationReader(
			lggr,
			selector,
			chainClient,
			executorConfig.OffRampAddresses[strSel],
			executorConfig.GetCCVInfoCacheExpiry(),
		)

		pk := os.Getenv(PK_ENV_VAR)
		if pk == "" {
			lggr.Errorf("Environment variable %s is not set", PK_ENV_VAR)
			os.Exit(1)
		}

		ct, err := contracttransmitter.NewEVMContractTransmitterFromRPC(
			ctx,
			lggr,
			selector,
			chain.Nodes[0].InternalHTTPUrl,
			pk,
			common.HexToAddress(executorConfig.OffRampAddresses[strSel]),
		)
		if err != nil {
			lggr.Errorw("Failed to create contract transmitter", "error", err)
			os.Exit(1)
		}

		destReaders[protocol.ChainSelector(selector)] = dr
		contractTransmitters[protocol.ChainSelector(selector)] = ct
	}

	// create indexer client which implements MessageReader and VerifierResultReader
	indexerClient := storageaccess.NewIndexerAPIReader(lggr, executorConfig.IndexerAddress)

	// create executor
	ex := x.NewChainlinkExecutor(lggr, contractTransmitters, destReaders, indexerClient, executorMonitoring)

	// create hash-based leader elector
	le := leaderelector.NewHashBasedLeaderElector(
		lggr,
		executorConfig.ExecutorPool,
		executorConfig.ExecutorID,
		executorConfig.GetExecutionInterval(),
		executorConfig.GetMinWaitPeriod(),
	)

	indexerStream := ccvstreamer.NewIndexerStorageStreamer(
		lggr,
		ccvstreamer.IndexerStorageConfig{
			IndexerClient:   indexerClient,
			LastQueryTime:   time.Now().Add(-1 * executorConfig.GetLookbackWindow()).Unix(),
			PollingInterval: executorConfig.GetPollingInterval(),
			Backoff:         executorConfig.GetBackoffDuration(),
			QueryLimit:      executorConfig.IndexerQueryLimit,
		})

	// Create executor coordinator
	coordinator, err := executor.NewCoordinator(
		executor.WithLogger(lggr),
		executor.WithExecutor(ex),
		executor.WithLeaderElector(le),
		executor.WithMessageSubscriber(indexerStream),
		executor.WithMonitoring(executorMonitoring),
	)
	if err != nil {
		lggr.Errorw("Failed to create execution coordinator", "error", err)
		os.Exit(1)
	}

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Failed to start execution coordinator", "error", err)
		os.Exit(1)
	}

	<-sigCh
	lggr.Infow("🛑 Shutdown signal received, stopping verifier...")

	// Graceful shutdown
	_, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop execution coordinator
	if err := coordinator.Close(); err != nil {
		lggr.Errorw("Execution coordinator stop error", "error", err)
	}

	lggr.Infow("✅ Execution service stopped gracefully")
}

func loadConfiguration(filepath string) (*executor.Configuration, error) {
	var config executor.Configuration
	if _, err := toml.DecodeFile(filepath, &config); err != nil {
		return nil, err
	}
	return &config, nil
}
