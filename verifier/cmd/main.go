package main

import (
	"context"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/smartcontractkit/chainlink-evm/pkg/config/chaintype"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/common/pkg/types"
	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/reader"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/verifier_config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	verifiertypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"
)

// Configuration flags
const (
	enableContinuousEventMonitoring = true // Set to true when RPC connectivity is stable
)

func loadConfiguration(filepath string) (*verifier_config.Configuration, error) {
	var config verifier_config.Configuration
	if _, err := toml.DecodeFile(filepath, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func logBlockchainInfo(blockchainHelper *types.BlockchainHelper, lggr logger.Logger) {
	for _, chainSelector := range []protocol.ChainSelector{1337, 2337} {
		logChainInfo(blockchainHelper, chainSelector, lggr)
	}
}

func logChainInfo(blockchainHelper *types.BlockchainHelper, chainSelector protocol.ChainSelector, lggr logger.Logger) {
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

	// Use actual blockchain information from configuration
	var blockchainHelper *types.BlockchainHelper
	if len(verifierConfig.BlockchainInfos) == 0 {
		lggr.Warnw("⚠️ No blockchain information in config")
	} else {
		blockchainHelper = types.NewBlockchainHelper(verifierConfig.BlockchainInfos)
		lggr.Infow("✅ Using real blockchain information from environment",
			"chainCount", len(verifierConfig.BlockchainInfos))
		logBlockchainInfo(blockchainHelper, lggr)
	}

	// Create verifier addresses before source readers setup
	verifierAddr, err := protocol.NewUnknownAddressFromHex(verifierConfig.CCVProxy1337)
	if err != nil {
		lggr.Errorw("Failed to create verifier address", "error", err)
		os.Exit(1)
	}

	verifierAddr2, err := protocol.NewUnknownAddressFromHex(verifierConfig.CCVProxy2337)
	if err != nil {
		lggr.Errorw("Failed to create verifier address", "error", err)
		os.Exit(1)
	}

	// Test multinode chain client connection and create real source readers
	var sourceReaders map[protocol.ChainSelector]reader.SourceReader
	if blockchainHelper != nil {
		chainClient := testMultinodeChainClient(ctx, blockchainHelper, verifierConfig, lggr)
		if chainClient != nil && (verifierConfig.CCVProxy1337 != "" || verifierConfig.CCVProxy2337 != "") {
			// Create blockchain source readers instead of mock ones
			sourceReaders = make(map[protocol.ChainSelector]reader.SourceReader)

			if verifierConfig.CCVProxy1337 != "" {
				blockchainSourceReader1337 := reader.NewEVMSourceReader(
					chainClient,
					verifierConfig.CCVProxy1337,
					protocol.ChainSelector(1337),
					lggr,
				)
				sourceReaders[protocol.ChainSelector(1337)] = blockchainSourceReader1337
			}

			if verifierConfig.CCVProxy2337 != "" {
				blockchainSourceReader2337 := reader.NewEVMSourceReader(
					chainClient,
					verifierConfig.CCVProxy2337,
					protocol.ChainSelector(2337),
					lggr,
				)
				sourceReaders[protocol.ChainSelector(2337)] = blockchainSourceReader2337
			}

			var chains []int
			for chainSelector := range sourceReaders {
				chains = append(chains, int(chainSelector))
			}
			lggr.Infow("✅ Created blockchain source readers", "chains", chains)
		} else {
			lggr.Warnw("⚠️ Chain client not available, falling back to mock source readers")
			// Fallback to mock readers
			mockSetup1337 := internal.SetupDevSourceReader(protocol.ChainSelector(1337))
			mockSetup2337 := internal.SetupDevSourceReader(protocol.ChainSelector(2337))

			sourceReaders = map[protocol.ChainSelector]reader.SourceReader{
				protocol.ChainSelector(1337): mockSetup1337.Reader,
				protocol.ChainSelector(2337): mockSetup2337.Reader,
			}

			// Start mock message generators for development
			internal.StartMockMessageGenerator(ctx, mockSetup1337, protocol.ChainSelector(1337), verifierAddr, lggr)
			internal.StartMockMessageGenerator(ctx, mockSetup2337, protocol.ChainSelector(2337), verifierAddr2, lggr)
		}
	} else {
		// No blockchain helper, use mock readers
		mockSetup1337 := internal.SetupDevSourceReader(protocol.ChainSelector(1337))
		mockSetup2337 := internal.SetupDevSourceReader(protocol.ChainSelector(2337))

		sourceReaders = map[protocol.ChainSelector]reader.SourceReader{
			protocol.ChainSelector(1337): mockSetup1337.Reader,
			protocol.ChainSelector(2337): mockSetup2337.Reader,
		}

		// Start mock message generators for development
		internal.StartMockMessageGenerator(ctx, mockSetup1337, protocol.ChainSelector(1337), verifierAddr, lggr)
		internal.StartMockMessageGenerator(ctx, mockSetup2337, protocol.ChainSelector(2337), verifierAddr2, lggr)
	}

	storage, err := storageaccess.CreateAggregatorAdapter(verifierConfig.AggregatorAddress, lggr)
	if err != nil {
		lggr.Errorw("Failed to create storage writer", "error", err)
		os.Exit(1)
	}
	storageWriter := storage

	// Create coordinator configuration
	config := verifiertypes.CoordinatorConfig{
		VerifierID: "dev-verifier-1",
		SourceConfigs: map[protocol.ChainSelector]verifiertypes.SourceConfig{
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
	copy(privateKey, []byte(verifierConfig.PrivateKey)) // Mock key
	signer, err := commit.NewECDSAMessageSigner(privateKey)
	if err != nil {
		lggr.Errorw("Failed to create message signer", "error", err)
		os.Exit(1)
	}
	lggr.Infow("Using verifier address", "address", signer.GetSignerAddress().String())

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

func ptr[T any](t T) *T { return &t }

// testMultinodeChainClient tests the multinode chain client connection and returns the client
func testMultinodeChainClient(ctx context.Context, blockchainHelper *types.BlockchainHelper, config *verifier_config.Configuration, lggr logger.Logger) client.Client {
	// Test for chain 1337
	chainSelector := protocol.ChainSelector(1337)

	blockchainInfo, err := blockchainHelper.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		lggr.Errorw("Failed to get blockchain info", "error", err, "chainSelector", chainSelector)
		return nil
	}

	noNewHeadsThreshold := 3 * time.Minute
	selectionMode := ptr("HighestHead")
	leaseDuration := 0 * time.Second
	pollFailureThreshold := ptr(uint32(5))
	pollInterval := 10 * time.Second
	syncThreshold := ptr(uint32(5))
	nodeIsSyncingEnabled := ptr(false)
	chainTypeStr := blockchainInfo.Type
	finalizedBlockOffset := ptr[uint32](16)
	enforceRepeatableRead := ptr(true)
	deathDeclarationDelay := time.Second * 3
	noNewFinalizedBlocksThreshold := time.Second * 5
	finalizedBlockPollInterval := time.Second * 4
	newHeadsPollInterval := time.Second * 4
	confirmationTimeout := time.Second * 60
	wsURL, _ := blockchainHelper.GetInternalWebsocketEndpoint(chainSelector)
	httpURL, _ := blockchainHelper.GetInternalRPCEndpoint(chainSelector)
	nodeConfigs := []client.NodeConfig{
		{
			Name:    ptr(blockchainInfo.ContainerName),
			WSURL:   ptr(wsURL),
			HTTPURL: ptr(httpURL),
		},
	}
	finalityDepth := ptr(uint32(10))
	safeDepth := ptr(uint32(6))
	finalityTagEnabled := ptr(true)
	lggr.Infow("🔍 Testing multinode chain client", "chainSelector", chainSelector, "wsURL", wsURL, "httpURL", httpURL)
	chainCfg, nodePool, nodes, err := client.NewClientConfigs(selectionMode, leaseDuration, chainTypeStr, nodeConfigs,
		pollFailureThreshold, pollInterval, syncThreshold, nodeIsSyncingEnabled, noNewHeadsThreshold, finalityDepth,
		finalityTagEnabled, finalizedBlockOffset, enforceRepeatableRead, deathDeclarationDelay, noNewFinalizedBlocksThreshold,
		finalizedBlockPollInterval, newHeadsPollInterval, confirmationTimeout, safeDepth)

	chainClient, err := client.NewEvmClient(nodePool, chainCfg, nil, lggr, big.NewInt(1337), nodes, chaintype.ChainType(chainTypeStr))

	if err != nil {
		lggr.Errorw("Failed to create multinode chain client", "error", err)
		return nil
	}
	// defer chainClient.Close()

	lggr.Infow("✅ Multinode chain client created successfully",
		"chainSelector", chainSelector,
		"nodeStates", chainClient.NodeStates())

	err = chainClient.Dial(ctx)
	if err != nil {
		lggr.Errorw("Failed to dial multinode chain client", "error", err)
		return nil
	}

	// Test 1: Get latest block using multinode's SelectRPC
	latestBlock, err := chainClient.LatestBlockHeight(ctx)
	if err != nil {
		lggr.Errorw("Failed to get latest block", "error", err)
		return nil
	}
	lggr.Infow("📦 Latest block (via multinode)", "blockNumber", latestBlock)

	// Test 2: Get chain ID
	chainID := chainClient.ConfiguredChainID()
	lggr.Infow("🔗 Chain ID", "chainID", chainID)

	// Test 3: Get a specific block header
	header, err := chainClient.HeadByNumber(ctx, latestBlock)
	if err != nil {
		lggr.Errorw("Failed to get block header", "error", err)
		return nil
	}
	lggr.Infow("📋 Block header",
		"number", header.Number,
		"hash", header.Hash.Hex(),
		"timestamp", header.Timestamp)

	// Test 4: Subscribe to CCVProxy events if configured
	if config.CCVProxy1337 != "" {
		// testEventSubscription(ctx, chainClient, config.CCVProxy1337, "CCVProxy", lggr)

		// Continuous event monitoring (can be enabled/disabled via flag)
		if enableContinuousEventMonitoring {
			// Start continuous event monitoring loop using the same multinode client
			// Only start if the client is properly connected and can make RPC calls
			lggr.Infow("🔗 Testing multinode client RPC connectivity before starting continuous monitoring")

			// Test if we can actually make an RPC call
			testCtx, testCancel := context.WithTimeout(ctx, 10*time.Second)
			_, err := chainClient.LatestBlockHeight(testCtx)
			testCancel()

			if err != nil {
				lggr.Warnw("⚠️ Multinode client cannot make RPC calls, skipping continuous event monitoring",
					"error", err.Error(),
					"nodeStates", chainClient.NodeStates())
			} else {
				lggr.Infow("✅ Multinode client RPC test successful, starting continuous monitoring")
				// go startContinuousEventLoop(ctx, chainClient, config.CCVProxy1337, lggr)
			}
		} else {
			lggr.Infow("ℹ️ Continuous event monitoring is disabled (enableContinuousEventMonitoring=false)")
			lggr.Infow("💡 To enable: set enableContinuousEventMonitoring=true when RPC connectivity is stable")
		}
	}

	lggr.Infow("✅ Multinode chain client tests completed successfully!")
	return chainClient
}
