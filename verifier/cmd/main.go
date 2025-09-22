package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/grafana/pyroscope-go"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/common/pkg"
	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/reader"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"

	commontypes "github.com/smartcontractkit/chainlink-ccv/common/pkg/types"
	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	verifiertypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"
)

// Configuration flags.
const (
	// Chain IDs for blockchain client connections.
	chainIDA = protocol.ChainSelector(1337)
	chainIDB = protocol.ChainSelector(2337)

	// Actual chain selectors used in CCIP messages.
	chainSelectorA = protocol.ChainSelector(3379446385462418246)  // Maps to chain ID 1337
	chainSelectorB = protocol.ChainSelector(12922642891491394802) // Maps to chain ID 2337
)

func loadConfiguration(filepath string) (*commontypes.VerifierConfig, error) {
	var config commontypes.VerifierConfig
	if _, err := toml.DecodeFile(filepath, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func logBlockchainInfo(blockchainHelper *commontypes.BlockchainHelper, lggr logger.Logger) {
	for _, chainID := range []protocol.ChainSelector{chainIDA, chainIDB} {
		logChainInfo(blockchainHelper, chainID, lggr)
	}
}

func logChainInfo(blockchainHelper *commontypes.BlockchainHelper, chainSelector protocol.ChainSelector, lggr logger.Logger) {
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

	filePath := "verifier.toml"
	if len(os.Args) > 1 {
		filePath = os.Args[1]
	}
	envConfig := os.Getenv("VERIFIER_CONFIG")
	if envConfig != "" {
		filePath = envConfig
	}
	verifierConfig, err := loadConfiguration(filePath)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "verifier",
		ServerAddress:   "http://pyroscope:4040",
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
	var blockchainHelper *commontypes.BlockchainHelper
	var chainClient1 client.Client
	var chainClient2 client.Client
	if len(verifierConfig.BlockchainInfos) == 0 {
		lggr.Warnw("⚠️ No blockchain information in config")
	} else {
		blockchainHelper = commontypes.NewBlockchainHelper(verifierConfig.BlockchainInfos)
		lggr.Infow("✅ Using real blockchain information from environment",
			"chainCount", len(verifierConfig.BlockchainInfos))
		logBlockchainInfo(blockchainHelper, lggr)
		chainClient1 = pkg.CreateHealthyMultiNodeClient(ctx, blockchainHelper, lggr, chainIDA)
		chainClient2 = pkg.CreateHealthyMultiNodeClient(ctx, blockchainHelper, lggr, chainIDB)
	}

	// Create verifier addresses before source readers setup
	verifierAddr, err := protocol.NewUnknownAddressFromHex(verifierConfig.VerifierOnRamp1337)
	if err != nil {
		lggr.Errorw("Failed to create verifier address", "error", err)
		os.Exit(1)
	}

	verifierAddr2, err := protocol.NewUnknownAddressFromHex(verifierConfig.VerifierOnRamp2337)
	if err != nil {
		lggr.Errorw("Failed to create verifier address", "error", err)
		os.Exit(1)
	}

	storageWriter, err := storageaccess.NewAggregatorWriter(verifierConfig.AggregatorAddress, lggr)
	if err != nil {
		lggr.Errorw("Failed to create storage writer", "error", err)
	}

	// Create source readers - either blockchain-based or mock
	sourceReaders := make(map[protocol.ChainSelector]reader.SourceReader)

	// Try to create blockchain source readers if possible
	if chainClient1 == nil || verifierConfig.VerifierOnRamp1337 == "" {
		lggr.Errorw("No chainclient or VerifierOnRamp1337 address", "chain", 1337)
		os.Exit(1)
	}
	sourceReaders[chainSelectorA] = reader.NewEVMSourceReader(chainClient1, verifierConfig.CCVProxy1337, chainIDA, lggr)
	lggr.Infow("✅ Created blockchain source reader", "chain", 1337)

	if chainClient2 == nil || verifierConfig.VerifierOnRamp2337 == "" {
		lggr.Errorw("No chainclient or VerifierOnRamp2337 address", "chain", 2337)
		os.Exit(1)
	}
	sourceReaders[chainSelectorB] = reader.NewEVMSourceReader(chainClient2, verifierConfig.CCVProxy2337, chainIDB, lggr)
	lggr.Infow("✅ Created blockchain source reader", "chain", 2337)

	// Create coordinator configuration
	config := verifiertypes.CoordinatorConfig{
		VerifierID: "dev-verifier-1",
		SourceConfigs: map[protocol.ChainSelector]verifiertypes.SourceConfig{
			chainSelectorA: {
				VerifierAddress: verifierAddr,
			},
			chainSelectorB: {
				VerifierAddress: verifierAddr2,
			},
		},
		ProcessingChannelSize: 1000,
		ProcessingTimeout:     30 * time.Second,
		MaxBatchSize:          100,
	}

	// Create message signer (mock for development)
	privateKey := make([]byte, 32)
	copy(privateKey, []byte(verifierConfig.PrivateKey)) // Mock key
	signer, err := commit.NewECDSAMessageSigner(privateKey)
	if err != nil {
		lggr.Errorw("Failed to create message signer", "error", err)
		os.Exit(1)
	}
	lggr.Infow("Using signer address", "address", signer.GetSignerAddress().String())

	// Create commit verifier
	commitVerifier := commit.NewCommitVerifier(config, signer, lggr)

	// Create verification coordinator
	coordinator, err := internal.NewVerificationCoordinator(
		internal.WithVerifier(commitVerifier),
		internal.WithSourceReaders(sourceReaders),
		internal.WithStorage(storageWriter),
		internal.WithConfig(config),
		internal.WithLogger(lggr),
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator", "error", err)
		os.Exit(1)
	}

	// Start the verification coordinator
	lggr.Infow("🚀 Starting Verification Coordinator",
		"verifierID", config.VerifierID,
		"sourceChains", []protocol.ChainSelector{chainSelectorA, chainSelectorB},
		"verifierAddress", []string{verifierAddr.String(), verifierAddr2.String()},
	)

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Failed to start verification coordinator", "error", err)
		os.Exit(1)
	}

	// Setup HTTP server for health checks and status
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		lggr.Infow("✅ CCV Verifier is running!\n")
		lggr.Infow("Verifier ID: %s\n", config.VerifierID)
		lggr.Infow("Source Chains: [%d, %d]\n", chainSelectorA, chainSelectorB)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := coordinator.HealthCheck(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			lggr.Infow("❌ Unhealthy: %s\n", err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		lggr.Infow("✅ Healthy\n")
	})

	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := storageWriter.GetStats()
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
	if err := coordinator.Stop(); err != nil {
		lggr.Errorw("Coordinator stop error", "error", err)
	}

	lggr.Infow("✅ Verifier service stopped gracefully")
}
