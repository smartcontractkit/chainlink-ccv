package main

import (
	"context"
	"fmt"
	"net/http"
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
	adapter "github.com/smartcontractkit/chainlink-ccv/executor/pkg/adapter"
	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/backofftimeprovider"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/destinationreader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	configPathEnvVar = "EXECUTOR_CONFIG_PATH"
	privateKeyEnvVar = "EXECUTOR_TRANSMITTER_PRIVATE_KEY"
	// indexerPollingInterval describes how frequently we ask indexer for new messages.
	// This should be kept at 1s for consistent behavior across all executors.
	indexerPollingInterval = 1 * time.Second
	// indexerGarbagecollectionInterval describes how frequently we garbage collect message duplicates from the indexer results
	// if this is too short, we will assume a message is net new every time it is read from the indexer.
	indexerGarbageCollectionInterval = 1 * time.Hour
	// messageContextWindow is the time window we use to expire duplicate messages from the indexer.
	// this combines with indexerGarbageCollectionInterval to avoid memory leak in the streamer.
	// We store messages for messageContextWindow, cleaning up old messages every indexerGarbageCollectionInterval.
	messageContextWindow = 9 * time.Hour
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

	//
	// Initialize logger
	// ------------------------------------------------------------------------------------------------
	// Keeping it at info level because debug will spam the logs with a lot of RPC caller related logs.
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}
	lggr = logger.Named(lggr, "executor")

	executorConfig, blockchainInfo, err := loadConfiguration(configPath)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "path", configPath, "error", err)
		os.Exit(1)
	}
	if err = executorConfig.Validate(); err != nil {
		lggr.Errorw("Failed to validate configuration", "path", configPath, "error", err)
		os.Exit(1)
	}

	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "executor",
		ServerAddress:   executorConfig.PyroscopeURL,
		Logger:          nil, // Disable pyroscope logging - so noisy
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
	lggr.Infow("Blockchain information", "blockchainInfo", blockchainInfo)

	//
	// Setup OTEL Monitoring (via beholder)
	// ------------------------------------------------------------------------------------------------
	var executorMonitoring executor.Monitoring
	if executorConfig.Monitoring.Enabled && executorConfig.Monitoring.Type == "beholder" {
		beholderConfig := beholder.Config{
			InsecureConnection:       executorConfig.Monitoring.Beholder.InsecureConnection,
			CACertFile:               executorConfig.Monitoring.Beholder.CACertFile,
			OtelExporterHTTPEndpoint: executorConfig.Monitoring.Beholder.OtelExporterHTTPEndpoint,
			OtelExporterGRPCEndpoint: executorConfig.Monitoring.Beholder.OtelExporterGRPCEndpoint,
			LogStreamingEnabled:      executorConfig.Monitoring.Beholder.LogStreamingEnabled,
			MetricReaderInterval:     time.Second * time.Duration(executorConfig.Monitoring.Beholder.MetricReaderInterval),
			TraceSampleRatio:         executorConfig.Monitoring.Beholder.TraceSampleRatio,
			TraceBatchTimeout:        time.Second * time.Duration(executorConfig.Monitoring.Beholder.TraceBatchTimeout),
			// TODO add CSA auth when run in standalone mode
			// AuthPublicKeyHex: ...,
			// AuthHeaders: ...,
			// Note: due to OTEL spec, all histogram buckets must be defined when the beholder client is created.
			MetricViews: monitoring.MetricViews(),
		}

		// Create the beholder client
		beholderClient, err := beholder.NewClient(beholderConfig)
		if err != nil {
			lggr.Fatalf("Failed to create beholder client: %v", err)
		}

		// Set the beholder client and global otel providers
		beholder.SetClient(beholderClient)
		beholder.SetGlobalOtelProviders()

		executorMonitoring, err = monitoring.InitMonitoring()
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
	contractTransmitters := make(map[protocol.ChainSelector]chainaccess.ContractTransmitter)
	destReaders := make(map[protocol.ChainSelector]chainaccess.DestinationReader)
	rmnReaders := make(map[protocol.ChainSelector]chainaccess.RMNCurseReader)
	for strSel, chain := range blockchainInfo {
		chainConfig := executorConfig.ChainConfiguration[strSel]
		selector, err := strconv.ParseUint(strSel, 10, 64)
		if err != nil {
			lggr.Errorw("Invalid chain selector in configuration", "error", err, "chainSelector", strSel)
			continue
		}

		chainClient := pkg.CreateMultiNodeClientFromInfo(ctx, chain, lggr)
		dr, err := destinationreader.NewEvmDestinationReader(
			destinationreader.Params{
				Lggr:                      lggr,
				ChainSelector:             protocol.ChainSelector(selector),
				ChainClient:               chainClient,
				OfframpAddress:            chainConfig.OffRampAddress,
				RmnRemoteAddress:          chainConfig.RmnAddress,
				CacheExpiry:               executorConfig.ReaderCacheExpiry,
				ExecutionVisabilityWindow: executorConfig.MaxRetryDuration,
				Monitoring:                executorMonitoring,
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
		Metrics:     executorMonitoring.Metrics(),
		RmnReaders:  rmnReaders,
		CacheExpiry: executorConfig.ReaderCacheExpiry,
	})

	//
	// Initialize indexer adapter with multiple clients (supports concurrent queries)
	// ------------------------------------------------------------------------------------------------
	httpClient := &http.Client{Timeout: 30 * time.Second}
	verifierResultReader, err := adapter.NewIndexerReaderAdapter(
		executorConfig.IndexerAddress,
		httpClient,
		executorMonitoring,
		lggr,
	)
	if err != nil {
		lggr.Errorw("Failed to create indexer adapter", "error", err)
		os.Exit(1)
	}

	//
	// Parse per chain configuration from executor configuration
	// ------------------------------------------------------------------------------------------------
	execPool := make(map[protocol.ChainSelector][]string)
	execIntervals := make(map[protocol.ChainSelector]time.Duration)
	defaultExecutorAddresses := make(map[protocol.ChainSelector]protocol.UnknownAddress)

	for strSel, chainConfig := range executorConfig.ChainConfiguration {
		selector, err := strconv.ParseUint(strSel, 10, 64)
		if err != nil {
			lggr.Errorw("Invalid chain selector in configuration", "error", err, "chainSelector", strSel)
			continue
		}
		execPool[protocol.ChainSelector(selector)] = chainConfig.ExecutorPool
		execIntervals[protocol.ChainSelector(selector)] = chainConfig.ExecutionInterval
		defaultExecutorAddresses[protocol.ChainSelector(selector)], err = protocol.NewUnknownAddressFromHex(chainConfig.DefaultExecutorAddress)
		if err != nil {
			lggr.Errorw("Invalid default executor address in configuration", "error", err, "chainSelector", strSel)
			continue
		}
	}

	//
	// Initialize Message Handler
	// ------------------------------------------------------------------------------------------------
	ex := x.NewChainlinkExecutor(lggr, contractTransmitters, destReaders, curseChecker, verifierResultReader, executorMonitoring, defaultExecutorAddresses)

	//
	// Initialize leader elector
	// ------------------------------------------------------------------------------------------------
	le := leaderelector.NewHashBasedLeaderElector(
		lggr,
		execPool,
		executorConfig.ExecutorID,
		execIntervals,
	)
	timeProvider := backofftimeprovider.NewBackoffNTPProvider(lggr, executorConfig.BackoffDuration, executorConfig.NtpServer)

	indexerStream := ccvstreamer.NewIndexerStorageStreamer(
		lggr,
		ccvstreamer.IndexerStorageConfig{
			IndexerClient:    verifierResultReader,
			InitialQueryTime: time.Now().Add(-1 * executorConfig.LookbackWindow),
			PollingInterval:  indexerPollingInterval,
			Backoff:          executorConfig.BackoffDuration,
			QueryLimit:       executorConfig.IndexerQueryLimit,
			ExpiryDuration:   messageContextWindow,
			CleanInterval:    indexerGarbageCollectionInterval,
			TimeProvider:     timeProvider,
		})

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
		executorConfig.WorkerCount,
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

func loadConfiguration(filepath string) (*executor.Configuration, map[string]*blockchain.Info, error) {
	var config executor.ConfigWithBlockchainInfo
	if _, err := toml.DecodeFile(filepath, &config); err != nil {
		return nil, nil, err
	}

	normalizedConfig, err := config.GetNormalizedConfig()
	if err != nil {
		return nil, nil, err
	}
	return normalizedConfig, config.BlockchainInfos, nil
}
