package main

import (
	"context"
	"encoding/binary"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smartcontractkit/chainlink-evm/pkg/config/chaintype"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/common/pkg/types"
	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/reader"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	verifiertypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"
)

// Configuration flags
const (
	enableContinuousEventMonitoring = true // Set to true when RPC connectivity is stable
)

func loadConfiguration(filepath string) (*config.Configuration, error) {
	var config config.Configuration
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

	// Test multinode chain client connection
	if blockchainHelper != nil {
		testMultinodeChainClient(ctx, blockchainHelper, verifierConfig, lggr)
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

func ptr[T any](t T) *T { return &t }

// testMultinodeChainClient tests the multinode chain client connection
func testMultinodeChainClient(ctx context.Context, blockchainHelper *types.BlockchainHelper, config *config.Configuration, lggr logger.Logger) {
	// Test for chain 1337
	chainSelector := protocol.ChainSelector(1337)

	blockchainInfo, err := blockchainHelper.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		lggr.Errorw("Failed to get blockchain info", "error", err, "chainSelector", chainSelector)
		return
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
		return
	}
	// defer chainClient.Close()

	lggr.Infow("✅ Multinode chain client created successfully",
		"chainSelector", chainSelector,
		"nodeStates", chainClient.NodeStates())

	err = chainClient.Dial(ctx)
	if err != nil {
		lggr.Errorw("Failed to dial multinode chain client", "error", err)
		return
	}

	// Test 1: Get latest block using multinode's SelectRPC
	latestBlock, err := chainClient.LatestBlockHeight(ctx)
	if err != nil {
		lggr.Errorw("Failed to get latest block", "error", err)
		return
	}
	lggr.Infow("📦 Latest block (via multinode)", "blockNumber", latestBlock)

	// Test 2: Get chain ID
	chainID := chainClient.ConfiguredChainID()
	lggr.Infow("🔗 Chain ID", "chainID", chainID)

	// Test 3: Get a specific block header
	header, err := chainClient.HeadByNumber(ctx, latestBlock)
	if err != nil {
		lggr.Errorw("Failed to get block header", "error", err)
		return
	}
	lggr.Infow("📋 Block header",
		"number", header.Number,
		"hash", header.Hash.Hex(),
		"timestamp", header.Timestamp)

	// Test 4: Subscribe to CCVProxy events if configured
	if config.CCVProxy1337 != "" {
		testEventSubscription(ctx, chainClient, config.CCVProxy1337, "CCVProxy", lggr)

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
				go startContinuousEventLoop(ctx, chainClient, config.CCVProxy1337, lggr)
			}
		} else {
			lggr.Infow("ℹ️ Continuous event monitoring is disabled (enableContinuousEventMonitoring=false)")
			lggr.Infow("💡 To enable: set enableContinuousEventMonitoring=true when RPC connectivity is stable")
		}
	}

	lggr.Infow("✅ Multinode chain client tests completed successfully!")
}

// testEventSubscription tests subscribing to CCIPMessageSent events
func testEventSubscription(ctx context.Context, chainClient client.Client, contractAddress string, contractType string, lggr logger.Logger) {
	lggr.Infow("📡 Testing event subscription", "contractType", contractType, "contract", contractAddress)

	// Parse contract address
	contractAddr := common.HexToAddress(contractAddress)

	// Calculate CCIPMessageSent event topic
	ccipMessageSentTopic := crypto.Keccak256Hash([]byte(
		"CCIPMessageSent(uint64,uint64,((bytes32,uint64,uint64,uint64),address,bytes,bytes,address,uint256,uint256,((address,bytes,uint256,bytes,(address,uint64,uint32,uint256,bytes)))[],((address,uint64,uint32,uint256,bytes))[],((address,uint64,uint32,uint256,bytes))),bytes[])",
	))

	// Create filter query
	query := ethereum.FilterQuery{
		Addresses: []common.Address{contractAddr},
		Topics:    [][]common.Hash{{ccipMessageSentTopic}},
	}

	// Create channel for receiving logs
	logsCh := make(chan ethtypes.Log, 10)

	// Subscribe to events
	subscription, err := chainClient.SubscribeFilterLogs(ctx, query, logsCh)
	if err != nil {
		lggr.Errorw("Failed to subscribe to CCIPMessageSent events", "error", err, "contractType", contractType)
		return
	}
	defer subscription.Unsubscribe()

	lggr.Infow("✅ Successfully subscribed to CCIPMessageSent events", "contractType", contractType, "topic", ccipMessageSentTopic.Hex())

	// Test sending a message to trigger an event (in background)
	go func() {
		time.Sleep(2 * time.Second) // Let subscription setup
		sendTestMessage(chainClient, contractAddr, contractType, lggr)
	}()

	// Wait for event with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	select {
	case log := <-logsCh:
		lggr.Infow("🎉 Received SimpleCCVProxy CCIPMessageSent event!",
			"blockNumber", log.BlockNumber,
			"txHash", log.TxHash.Hex(),
			"topicCount", len(log.Topics),
			"dataLength", len(log.Data))

		// Parse the event data
		parseCCIPMessageSentEvent(log, contractType, lggr)

	case <-timeoutCtx.Done():
		lggr.Warnw("⏱️ Timeout waiting for CCIPMessageSent event", "timeout", "30s", "contractType", contractType)

	case err := <-subscription.Err():
		lggr.Errorw("❌ Subscription error", "error", err)
	}
}

// sendTestMessage sends a test message to trigger an event
func sendTestMessage(chainClient client.Client, contractAddr common.Address, contractType string, lggr logger.Logger) {
	lggr.Infow("📤 Sending test message", "contractType", contractType, "contract", contractAddr.Hex())

	// For now, just log that we would send a message
	// In a full implementation, we'd create a transaction here to call dev_send() or send()
	lggr.Infow("📝 Test message would be sent here (transaction creation not implemented in this test)")
}

// parseCCIPMessageSentEvent parses and logs the CCIPMessageSent event data
func parseCCIPMessageSentEvent(log ethtypes.Log, contractType string, lggr logger.Logger) {
	lggr.Infow("🔍 Parsing CCIPMessageSent event",
		"contractType", contractType,
		"address", log.Address.Hex(),
		"topics", len(log.Topics),
		"dataSize", len(log.Data))

	// Parse indexed topics
	if len(log.Topics) >= 3 {
		// Topic 0 is the event signature
		// Topic 1 is indexed destChainSelector
		// Topic 2 is indexed sequenceNumber
		destChainSelector := binary.BigEndian.Uint64(log.Topics[1][24:]) // Last 8 bytes
		sequenceNumber := binary.BigEndian.Uint64(log.Topics[2][24:])    // Last 8 bytes

		lggr.Infow("📊 Event details",
			"contractType", contractType,
			"destChainSelector", destChainSelector,
			"sequenceNumber", sequenceNumber,
			"eventSignature", log.Topics[0].Hex())
	}

	lggr.Infow("✅ CCIPMessageSent event parsing completed", "contractType", contractType)
}

// startContinuousEventLoop starts a continuous loop to monitor CCIPMessageSent events using the existing multinode client
func startContinuousEventLoop(ctx context.Context, chainClient client.Client, contractAddress string, lggr logger.Logger) {
	lggr.Infow("🔄 Starting continuous CCIPMessageSent event monitoring with multinode client")

	// Check if client is properly connected first
	if chainClient == nil {
		lggr.Errorw("❌ Chain client is nil, cannot start continuous event monitoring")
		return
	}

	// Add panic recovery to handle multinode client panics gracefully
	defer func() {
		if r := recover(); r != nil {
			lggr.Errorw("❌ [MULTINODE CONTINUOUS] Recovered from panic in event monitoring",
				"panic", r,
				"nodeStates", chainClient.NodeStates())
		}
	}()

	// Parse contract address
	contractAddr := common.HexToAddress(contractAddress)

	// Calculate CCIPMessageSent event topic
	ccipMessageSentTopic := "0xa816f7e08da08b1aa0143155f28f728327e40df7f707f612cb3566ab91229820"

	lggr.Infow("✅ Started continuous CCIPMessageSent event monitoring with multinode client using FilterLogs",
		"contract", contractAddress,
		"topic", ccipMessageSentTopic)

	// Track the last processed block to avoid duplicates
	var lastProcessedBlock *big.Int

	// Continuous event monitoring loop using FilterLogs
	ticker := time.NewTicker(15 * time.Second) // Poll every 15 seconds to reduce load further
	// defer ticker.Stop()

	// Add initial delay to let the client fully establish connections
	time.Sleep(10 * time.Second)
	lggr.Infow("⏳ Initial delay completed, starting event monitoring cycles")
	for {
		select {
		case <-ctx.Done():
			lggr.Infow("🛑 Stopping continuous event monitoring due to context cancellation")
			return

		case <-ticker.C:
			// Wrap the entire cycle in a function with its own panic recovery
			func() {
				defer func() {
					if r := recover(); r != nil {
						lggr.Warnw("⚠️ [MULTINODE CONTINUOUS] Recovered from panic in monitoring cycle, will retry",
							"panic", r)
					}
				}()

				lggr.Infow("⏱️ [MULTINODE CONTINUOUS] Starting new monitoring cycle",
					"contract", contractAddress,
					"lastProcessedBlock", lastProcessedBlock.String())
				// Check client connection status before making requests
				if len(chainClient.NodeStates()) == 0 {
					lggr.Warnw("⚠️ [MULTINODE CONTINUOUS] No nodes available, skipping this cycle")
					return
				}

				// Get current block number with error handling and timeout
				blockCtx, blockCancel := context.WithTimeout(ctx, 5*time.Second)
				currentBlock, err := chainClient.LatestBlockHeight(blockCtx)
				blockCancel()

				lggr.Infow("⏱️ [MULTINODE CONTINUOUS] Fetched latest block",
					"blockNumber", currentBlock.String())

				if err != nil {
					lggr.Warnw("⚠️ [MULTINODE CONTINUOUS] Failed to get latest block, will retry",
						"error", err.Error(),
						"nodeStates", chainClient.NodeStates())
					return
				}

				// Set query range - look at recent blocks
				var fromBlock *big.Int
				if lastProcessedBlock == nil {
					// For the first run, look at last 100 blocks to catch recent events (reduced further)
					if currentBlock.Cmp(big.NewInt(100)) > 0 {
						fromBlock = new(big.Int).Sub(currentBlock, big.NewInt(100))
					} else {
						fromBlock = big.NewInt(1)
					}
				} else {
					fromBlock = new(big.Int).Add(lastProcessedBlock, big.NewInt(1))
				}

				// Only query if there are new blocks
				if fromBlock.Cmp(currentBlock) > 0 {
					return
				}

				// Create query with block range
				rangeQuery := ethereum.FilterQuery{
					FromBlock: fromBlock,
					ToBlock:   currentBlock,
					Addresses: []common.Address{contractAddr},
					Topics:    [][]common.Hash{{common.HexToHash(ccipMessageSentTopic)}},
				}

				lggr.Infow("🔍 [MULTINODE CONTINUOUS] Querying logs",
					"fromBlock", fromBlock.String(),
					"toBlock", currentBlock.String())

				// Query for logs using FilterLogs with error handling and timeout
				logsCtx, logsCancel := context.WithTimeout(ctx, 5*time.Second)
				logs, err := chainClient.FilterLogs(logsCtx, rangeQuery)
				logsCancel()

				if err != nil {
					lggr.Warnw("⚠️ [MULTINODE CONTINUOUS] Failed to filter logs, will retry",
						"error", err.Error(),
						"fromBlock", fromBlock.String(),
						"toBlock", currentBlock.String())
					return
				}

				if len(logs) == 0 {
					lggr.Infow("🔍 [MULTINODE CONTINUOUS] No CCIPMessageSent events found in this cycle",
						"fromBlock", fromBlock.String(),
						"toBlock", currentBlock.String())
				}

				// Process any found logs
				for _, log := range logs {
					lggr.Infow("🎉 [MULTINODE CONTINUOUS] Found CCIPMessageSent event!",
						"blockNumber", log.BlockNumber,
						"txHash", log.TxHash.Hex(),
						"contract", log.Address.Hex(),
						"topicCount", len(log.Topics),
						"dataLength", len(log.Data))

					// Parse indexed topics for quick info
					if len(log.Topics) >= 3 {
						destChainSelector := binary.BigEndian.Uint64(log.Topics[1][24:]) // Last 8 bytes
						sequenceNumber := binary.BigEndian.Uint64(log.Topics[2][24:])    // Last 8 bytes

						lggr.Infow("📊 [MULTINODE CONTINUOUS] Event details",
							"destChainSelector", destChainSelector,
							"sequenceNumber", sequenceNumber,
							"timestamp", time.Now().Format("15:04:05.000"))
					}
				}

				// Update last processed block
				lastProcessedBlock = new(big.Int).Set(currentBlock)

				if len(logs) > 0 {
					lggr.Infow("📈 [MULTINODE CONTINUOUS] Processed block range",
						"fromBlock", fromBlock.String(),
						"toBlock", currentBlock.String(),
						"eventsFound", len(logs))
				} else {
					// Log successful query even if no events found (less verbose)
					lggr.Infow("🔍 [MULTINODE CONTINUOUS] No events found in range",
						"fromBlock", fromBlock.String(),
						"toBlock", currentBlock.String())
				}
			}()
		}
	}
}
