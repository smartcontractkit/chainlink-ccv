package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ethereum/go-ethereum/common"
	"github.com/grafana/pyroscope-go"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"

	commontypes "github.com/smartcontractkit/chainlink-ccv/integration/pkg/types"
)

const (
	PK_ENV_VAR  = "VERIFIER_SIGNER_PRIVATE_KEY"
	CONFIG_PATH = "VERIFIER_CONFIG_PATH"
)

func loadConfiguration(filepath string) (*commontypes.VerifierConfig, error) {
	var config commontypes.VerifierConfig
	if _, err := toml.DecodeFile(filepath, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func logBlockchainInfo(blockchainHelper *protocol.BlockchainHelper, lggr logger.Logger) {
	for _, chainID := range blockchainHelper.GetAllChainSelectors() {
		logChainInfo(blockchainHelper, chainID, lggr)
	}
}

func logChainInfo(blockchainHelper *protocol.BlockchainHelper, chainSelector protocol.ChainSelector, lggr logger.Logger) {
	if info, err := blockchainHelper.GetBlockchainInfo(chainSelector); err == nil {
		lggr.Infow("🔗 Blockchain available", "chainSelector", chainSelector, "info", info)
	}

	if rpcURL, err := blockchainHelper.GetRPCEndpoint(chainSelector); err == nil {
		lggr.Infow("🌐 RPC endpoint", "chainSelector", chainSelector, "url", rpcURL)
	}

	if wsURL, err := blockchainHelper.GetWebSocketEndpoint(chainSelector); err == nil {
		lggr.Infow("🔌 WebSocket endpoint", "chainSelector", chainSelector, "url", wsURL)
	}

	if internalURL, err := blockchainHelper.GetInternalRPCEndpoint(chainSelector); err == nil {
		lggr.Infow("🔒 Internal RPC endpoint", "chainSelector", chainSelector, "url", internalURL)
	}

	if nodes, err := blockchainHelper.GetAllNodes(chainSelector); err == nil {
		lggr.Infow("📡 All nodes", "chainSelector", chainSelector, "nodeCount", len(nodes))
	}
}

func main() {
	// Setup logging - always debug level for now
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	if err != nil {
		panic(err)
	}

	// Use SugaredLogger for better API
	lggr = logger.Sugared(lggr)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	filePath := "verifier-1.toml"
	if len(os.Args) > 1 {
		filePath = os.Args[1]
	}
	envConfig := os.Getenv(CONFIG_PATH)
	if envConfig != "" {
		filePath = envConfig
	}
	config, err := loadConfiguration(filePath)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "verifier",
		ServerAddress:   config.PyroscopeURL,
		Logger:          pyroscope.StandardLogger,
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

	// Use actual blockchain information from configuration
	var blockchainHelper *protocol.BlockchainHelper
	chainClients := make(map[protocol.ChainSelector]client.Client)
	if len(config.BlockchainInfos) == 0 {
		lggr.Warnw("⚠️ No blockchain information in config")
	} else {
		blockchainHelper = protocol.NewBlockchainHelper(config.BlockchainInfos)
		lggr.Infow("✅ Using real blockchain information from environment",
			"chainCount", len(config.BlockchainInfos))
		logBlockchainInfo(blockchainHelper, lggr)
		for _, selector := range blockchainHelper.GetAllChainSelectors() {
			lggr.Infow("Creating chain client", "chainSelector", selector)
			chainClients[selector] = pkg.CreateHealthyMultiNodeClient(ctx, blockchainHelper, lggr, selector)
		}
	}

	// Create verifier addresses before source readers setup
	verifierAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.CommitteeVerifierAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Errorw("Failed to create verifier address", "error", err)
			os.Exit(1)
		}
		verifierAddresses[selector] = addr
	}

	hmacConfig := &hmac.ClientConfig{
		APIKey: config.AggregatorAPIKey,
		Secret: config.AggregatorSecretKey,
	}

	aggregatorWriter, err := storageaccess.NewAggregatorWriter(config.AggregatorAddress, lggr, hmacConfig)
	if err != nil {
		lggr.Errorw("Failed to create aggregator writer", "error", err)
		os.Exit(1)
	}

	aggregatorReader, err := storageaccess.NewAggregatorReader(config.AggregatorAddress, lggr, 0, hmacConfig) // since=0 for checkpoint reads
	if err != nil {
		// Clean up writer if reader creation fails
		err := aggregatorWriter.Close()
		if err != nil {
			lggr.Errorw("Failed to close aggregator writer", "error", err)
		}
		lggr.Errorw("Failed to create aggregator reader", "error", err)
		os.Exit(1)
	}
	// Create checkpoint manager (includes both writer and reader)
	checkpointManager := storageaccess.NewAggregatorCheckpointManager(aggregatorWriter, aggregatorReader)

	// Create source readers - either blockchain-based or mock
	sourceReaders := make(map[protocol.ChainSelector]verifier.SourceReader)

	lggr.Infow("Committee verifier addresses", "addresses", config.CommitteeVerifierAddresses)
	// Try to create blockchain source readers if possible
	for _, selector := range blockchainHelper.GetAllChainSelectors() {
		lggr.Infow("Creating source reader", "chainSelector", selector, "strSelector", uint64(selector))
		strSelector := strconv.FormatUint(uint64(selector), 10)

		if config.CommitteeVerifierAddresses[strSelector] == "" {
			lggr.Errorw("Committee verifier address is not set", "chainSelector", selector)
			continue
		}
		if config.OnRampAddresses[strSelector] == "" {
			lggr.Errorw("On ramp address is not set", "chainSelector", selector)
			continue
		}

		sourceReaders[selector], err = sourcereader.NewEVMSourceReader(chainClients[selector], common.HexToAddress(config.OnRampAddresses[strSelector]), onramp.OnRampCCIPMessageSent{}.Topic().Hex(), selector, lggr)
		if err != nil {
			lggr.Errorw("Failed to create EVM source reader", "selector", selector, "error", err)
			continue
		}
		// sourceReaders[selector] = verifier.NewSourceReaderService(emvSourceReader, selector, checkpointManager, lggr)
		lggr.Infow("✅ Created blockchain source reader", "chain", selector)
	}

	// Create coordinator configuration
	sourceConfigs := make(map[protocol.ChainSelector]verifier.SourceConfig)
	for _, selector := range blockchainHelper.GetAllChainSelectors() {
		strSelector := strconv.FormatUint(uint64(selector), 10)
		sourceConfigs[selector] = verifier.SourceConfig{
			VerifierAddress: verifierAddresses[strSelector],
		}
	}

	coordinatorConfig := verifier.CoordinatorConfig{
		VerifierID:            config.VerifierID,
		SourceConfigs:         sourceConfigs,
		ProcessingChannelSize: 1000,
		ProcessingTimeout:     30 * time.Second,
		MaxBatchSize:          100,
	}

	pk := os.Getenv(PK_ENV_VAR)
	if pk == "" {
		lggr.Errorf("Environment variable %s is not set", PK_ENV_VAR)
		os.Exit(1)
	}
	// Create message signer (mock for development)
	privateKey := make([]byte, 32)
	copy(privateKey, pk) // Mock key
	signer, err := commit.NewECDSAMessageSigner(privateKey)
	if err != nil {
		lggr.Errorw("Failed to create message signer", "error", err)
		os.Exit(1)
	}
	lggr.Infow("Using signer address", "address", signer.GetSignerAddress().String())

	// Setup OTEL Monitoring (via beholder)
	verifierMonitoring, err := monitoring.InitMonitoring(beholder.Config{
		InsecureConnection:       config.Monitoring.Beholder.InsecureConnection,
		CACertFile:               config.Monitoring.Beholder.CACertFile,
		OtelExporterHTTPEndpoint: config.Monitoring.Beholder.OtelExporterHTTPEndpoint,
		OtelExporterGRPCEndpoint: config.Monitoring.Beholder.OtelExporterGRPCEndpoint,
		LogStreamingEnabled:      config.Monitoring.Beholder.LogStreamingEnabled,
		MetricReaderInterval:     time.Second * time.Duration(config.Monitoring.Beholder.MetricReaderInterval),
		TraceSampleRatio:         config.Monitoring.Beholder.TraceSampleRatio,
		TraceBatchTimeout:        time.Second * time.Duration(config.Monitoring.Beholder.TraceBatchTimeout),
	})
	if err != nil {
		lggr.Fatalf("Failed to initialize verifier monitoring: %v", err)
	}

	// Create commit verifier
	commitVerifier, err := commit.NewCommitVerifier(coordinatorConfig, signer, lggr, verifierMonitoring)
	if err != nil {
		lggr.Errorw("Failed to create commit verifier", "error", err)
		os.Exit(1)
	}

	// Create verification coordinator
	coordinator, err := verifier.NewVerificationCoordinator(
		verifier.WithVerifier(commitVerifier),
		verifier.WithSourceReaders(sourceReaders),
		verifier.WithCheckpointManager(checkpointManager),
		verifier.WithStorage(aggregatorWriter),
		verifier.WithConfig(coordinatorConfig),
		verifier.WithLogger(lggr),
		verifier.WithMonitoring(verifierMonitoring),
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator", "error", err)
		os.Exit(1)
	}

	// Start the verification coordinator
	lggr.Infow("🚀 Starting Verification Coordinator",
		"verifierID", coordinatorConfig.VerifierID,
		"verifierAddress", verifierAddresses,
	)

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Failed to start verification coordinator", "error", err)
		os.Exit(1)
	}

	// Setup HTTP server for health checks and status
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		lggr.Infow("✅ CCV Verifier is running!\n")
		lggr.Infow("Verifier ID: %s\n", coordinatorConfig.VerifierID)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := coordinator.Ready(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			lggr.Infow("❌ Unhealthy: %s\n", err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		lggr.Infow("✅ Healthy\n")
	})

	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := aggregatorWriter.GetStats()
		lggr.Infow("📊 Storage Statistics:\n")
		for key, value := range stats {
			lggr.Infow("%s: %v\n", key, value)
		}
	})

	// Start HTTP server
	server := &http.Server{Addr: ":8100", ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go func() {
		lggr.Infow("🌐 HTTP server starting", "port", "8100")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			lggr.Errorw("HTTP server error", "error", err)
		}
	}()

	lggr.Infow("🎯 Verifier service fully started and ready!")

	// Wait for shutdown signal
	<-sigCh
	lggr.Infow("🛑 Shutdown signal received, stopping verifier...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		lggr.Errorw("HTTP server shutdown error", "error", err)
	}

	// Stop verification coordinator
	if err := coordinator.Close(); err != nil {
		lggr.Errorw("Coordinator stop error", "error", err)
	}

	lggr.Infow("✅ Verifier service stopped gracefully")
}
