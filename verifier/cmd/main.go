package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/reader"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

func loadConfiguration(filepath string) (*config.Configuration, error) {
	var config config.Configuration
	if _, err := toml.DecodeFile(filepath, &config); err != nil {
		return nil, err
	}
	return &config, nil
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
	verifierConfig, err := loadConfiguration(filePath)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Demonstrate blockchain information usage (these would come from the environment in real usage)
	// For now, create mock blockchain information to show the integration
	mockBlockchainInfos := map[string]*internal.BlockchainInfo{
		"1337": {
			ChainID:       "1337",
			Type:          "anvil",
			Family:        "ethereum",
			ContainerName: "anvil-1337",
			Nodes: []*internal.Node{
				{
					ExternalHTTPUrl: "http://localhost:8545",
					InternalHTTPUrl: "http://anvil-1337:8545",
					ExternalWSUrl:   "ws://localhost:8546",
					InternalWSUrl:   "ws://anvil-1337:8546",
				},
			},
		},
		"2337": {
			ChainID:       "2337",
			Type:          "anvil",
			Family:        "ethereum",
			ContainerName: "anvil-2337",
			Nodes: []*internal.Node{
				{
					ExternalHTTPUrl: "http://localhost:8547",
					InternalHTTPUrl: "http://anvil-2337:8545",
					ExternalWSUrl:   "ws://localhost:8548",
					InternalWSUrl:   "ws://anvil-2337:8546",
				},
			},
		},
	}

	// Create blockchain helper to demonstrate usage
	blockchainHelper := internal.NewBlockchainHelper(mockBlockchainInfos)

	// Log blockchain information
	for _, chainSelector := range []protocol.ChainSelector{1337, 2337} {
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

	storage, err := storageaccess.CreateAggregatorAdapter(verifierConfig.AggregatorAddress, lggr)
	if err != nil {
		lggr.Errorw("Failed to create storage writer", "error", err)
		os.Exit(1)
	}
	storageWriter := storage

	// Create mock source readers for two chains (matching devenv setup)
	mockSetup1337 := internal.SetupDevSourceReader(protocol.ChainSelector(1337))
	mockSetup2337 := internal.SetupDevSourceReader(protocol.ChainSelector(2337))

	sourceReaders := map[protocol.ChainSelector]reader.SourceReader{
		protocol.ChainSelector(1337): mockSetup1337.Reader,
		protocol.ChainSelector(2337): mockSetup2337.Reader,
	}

	// Create verifier address
	verifierAddr, err := protocol.NewUnknownAddressFromHex("0xAAAA22bE3CAee4b8Cd9a407cc3ac1C251C2007B1")
	if err != nil {
		lggr.Errorw("Failed to create verifier address", "error", err)
		os.Exit(1)
	}

	verifierAddr2, err := protocol.NewUnknownAddressFromHex("0xBBBB22bE3CAee4b8Cd9a407cc3ac1C251C2007B1")
	if err != nil {
		lggr.Errorw("Failed to create verifier address", "error", err)
		os.Exit(1)
	}

	// Create coordinator configuration
	config := types.CoordinatorConfig{
		VerifierID: "dev-verifier-1",
		SourceConfigs: map[protocol.ChainSelector]types.SourceConfig{
			protocol.ChainSelector(1337): {
				VerifierAddress: verifierAddr,
			},
			protocol.ChainSelector(2337): {
				VerifierAddress: verifierAddr2,
			},
		},
		ProcessingChannelSize: 1000,
		ProcessingTimeout:     30 * time.Second,
		MaxBatchSize:          100,
	}

	// Create message signer (mock for development)
	privateKey := make([]byte, 32)
	copy(privateKey, "dev-private-key-12345678901234567890") // Mock key
	signer, err := commit.NewECDSAMessageSigner(privateKey)
	if err != nil {
		lggr.Errorw("Failed to create message signer", "error", err)
		os.Exit(1)
	}

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
		"sourceChains", []protocol.ChainSelector{1337, 2337},
		"verifierAddress", []string{verifierAddr.String(), verifierAddr2.String()},
	)

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Failed to start verification coordinator", "error", err)
		os.Exit(1)
	}

	// Start mock message generators for development
	internal.StartMockMessageGenerator(ctx, mockSetup1337, protocol.ChainSelector(1337), verifierAddr, lggr)
	internal.StartMockMessageGenerator(ctx, mockSetup2337, protocol.ChainSelector(2337), verifierAddr2, lggr)

	// Setup HTTP server for health checks and status
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		lggr.Infow("✅ CCV Verifier is running!\n")
		lggr.Infow("Verifier ID: %s\n", config.VerifierID)
		lggr.Infow("Source Chains: [1337, 2337]\n")
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
		stats := storage.GetStats()
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
