package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ethereum/go-ethereum/common"
	"github.com/grafana/pyroscope-go"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/backofftimeprovider"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/destinationreader"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
)

const (
	configPathEnvVar = "EXECUTOR_CONFIG_PATH"
	privateKeyEnvVar = "EXECUTOR_TRANSMITTER_PRIVATE_KEY"
	// indexerPollingInterval describes how frequently we ask indexer for new messages.
	// This should be kept at 1s for consistent behavior across all executors.
	indexerPollingInterval = 1 * time.Second
)

func main() {
	//
	// Load configuration
	// ------------------------------------------------------------------------------------------------
	configPath := executor.DefaultConfigFile
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}
	envConfig := os.Getenv(configPathEnvVar)
	if envConfig != "" {
		configPath = envConfig
	}

	executorConfig, err := loadConfiguration(configPath)
	if err != nil {
		os.Exit(1)
	}
	if err = executorConfig.Validate(); err != nil {
		os.Exit(1)
	}

	//
	// Initialize logger
	// ------------------------------------------------------------------------------------------------
	// Keeping it at info level because debug will spam the logs with a lot of RPC caller related logs.
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}
	lggr = logger.Named(lggr, "executor")

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

	//
	// Setup OTEL Monitoring (via beholder)
	// ------------------------------------------------------------------------------------------------
	var executorMonitoring executor.Monitoring
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

	//
	// Initialize Context
	// ------------------------------------------------------------------------------------------------
	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	//
	// Initialize executor components
	// ------------------------------------------------------------------------------------------------
	contractTransmitters := make(map[protocol.ChainSelector]executor.ContractTransmitter)
	destReaders := make(map[protocol.ChainSelector]executor.DestinationReader)
	rmnReaders := make(map[protocol.ChainSelector]ccvcommon.RMNRemoteReader)
	for strSel, chain := range executorConfig.BlockchainInfos {
		chainConfig := executorConfig.ChainConfiguration[strSel]
		selector, err := strconv.ParseUint(strSel, 10, 64)
		if err != nil {
			lggr.Errorw("Invalid chain selector in configuration", "error", err, "chainSelector", strSel)
			continue
		}

		chainClient := pkg.CreateMultiNodeClientFromInfo(ctx, chain, lggr)
		dr, err := destinationreader.NewEvmDestinationReader(
			destinationreader.Params{
				Lggr:             lggr,
				ChainSelector:    protocol.ChainSelector(selector),
				ChainClient:      chainClient,
				OfframpAddress:   chainConfig.OffRampAddress,
				RmnRemoteAddress: chainConfig.RmnAddress,
				CacheExpiry:      executorConfig.ReaderCacheExpiry,
			})
		if err != nil {
			lggr.Errorw("Failed to create destination reader", "error", err, "chainSelector", strSel)
		}

		pk := os.Getenv(privateKeyEnvVar)
		if pk == "" {
			lggr.Errorf("Environment variable %s is not set", privateKeyEnvVar)
			os.Exit(1)
		}

		ct, err := contracttransmitter.NewEVMContractTransmitterFromRPC(
			ctx,
			lggr,
			protocol.ChainSelector(selector),
			chain.Nodes[0].InternalHTTPUrl,
			pk,
			common.HexToAddress(chainConfig.OffRampAddress),
		)
		if err != nil {
			lggr.Errorw("Failed to create contract transmitter", "error", err)
			os.Exit(1)
		}
		if dr != nil {
			destReaders[protocol.ChainSelector(selector)] = dr
			rmnReaders[protocol.ChainSelector(selector)] = dr
		}
		contractTransmitters[protocol.ChainSelector(selector)] = ct
	}

	//
	// Initialize curse checker
	// ------------------------------------------------------------------------------------------------
	curseChecker := cursechecker.NewCachedCurseChecker(cursechecker.Params{
		Lggr:        lggr,
		RmnReaders:  rmnReaders,
		CacheExpiry: executorConfig.ReaderCacheExpiry,
	})

	//
	// Initialize indexer client
	// ------------------------------------------------------------------------------------------------
	indexerClient := storageaccess.NewIndexerAPIReader(lggr, executorConfig.IndexerAddress)

	//
	// Initialize Message Handler
	// ------------------------------------------------------------------------------------------------
	ex := x.NewChainlinkExecutor(lggr, contractTransmitters, destReaders, curseChecker, indexerClient, executorMonitoring)

	//
	// Initialize leader elector
	// ------------------------------------------------------------------------------------------------
	execPool := make(map[protocol.ChainSelector][]string)
	execIntervals := make(map[protocol.ChainSelector]time.Duration)
	for strSel, chainConfig := range executorConfig.ChainConfiguration {
		selector, err := strconv.ParseUint(strSel, 10, 64)
		if err != nil {
			lggr.Errorw("Invalid chain selector in configuration", "error", err, "chainSelector", strSel)
			continue
		}
		execPool[protocol.ChainSelector(selector)] = chainConfig.ExecutorPool
		execIntervals[protocol.ChainSelector(selector)] = chainConfig.ExecutionInterval
	}
	le := leaderelector.NewHashBasedLeaderElector(
		lggr,
		execPool,
		executorConfig.ExecutorID,
		execIntervals,
	)

	indexerStream := ccvstreamer.NewIndexerStorageStreamer(
		lggr,
		ccvstreamer.IndexerStorageConfig{
			IndexerClient:   indexerClient,
			LastQueryTime:   time.Now().Add(-1 * executorConfig.LookbackWindow).UnixMilli(),
			PollingInterval: indexerPollingInterval,
			Backoff:         executorConfig.BackoffDuration,
			QueryLimit:      executorConfig.IndexerQueryLimit,
		})

	timeProvider := backofftimeprovider.NewBackoffNTPProvider(lggr, executorConfig.BackoffDuration)
	//
	// Initialize executor coordinator
	// ------------------------------------------------------------------------------------------------
	coordinator, err := executor.NewCoordinator(
		lggr,
		ex,
		indexerStream,
		le,
		executorMonitoring,
		executorConfig.MaxRetryDuration,
		timeProvider,
	)
	if err != nil {
		lggr.Errorw("Failed to create execution coordinator", "error", err)
		os.Exit(1)
	}

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Failed to start execution coordinator", "error", err)
		os.Exit(1)
	}

	//
	// Wait for shutdown signal
	// ------------------------------------------------------------------------------------------------
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

	normalizedConfig, err := config.GetNormalizedConfig()
	if err != nil {
		return nil, err
	}
	return normalizedConfig, nil
}
