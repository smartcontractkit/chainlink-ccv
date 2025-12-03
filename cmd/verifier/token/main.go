package main

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/verifier/token/storage"

	"github.com/smartcontractkit/chainlink-ccv/verifier/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/lbtc"

	"github.com/BurntSushi/toml"
	"github.com/ethereum/go-ethereum/common"
	"github.com/grafana/pyroscope-go"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"

	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

const (
	ConfigPath = "TOKEN_VERIFIER_CONFIG_PATH"
)

func loadConfiguration(filepath string) (*token.Config, error) {
	var config token.Config
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
	// Debug level currently spams a lot of logs from the RPC callers.
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}
	lggr = logger.Named(lggr, "verifier")

	lggr.Infow("Starting")

	// Use SugaredLogger for better API
	lggr = logger.Sugared(lggr)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	filePath := verifier.DefaultConfigFile
	if len(os.Args) > 1 {
		filePath = os.Args[1]
	}
	envConfig := os.Getenv(ConfigPath)
	if envConfig != "" {
		filePath = envConfig
	}
	config, err := loadConfiguration(filePath)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "tokenVerifier",
		ServerAddress:   config.PyroscopeURL,
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

	// Use actual blockchain information from configuration
	var blockchainHelper *protocol.BlockchainHelper
	chainClients := make(map[protocol.ChainSelector]client.Client)
	if len(config.BlockchainInfos) == 0 {
		lggr.Warnw("No blockchain information in config")
	} else {
		blockchainHelper = protocol.NewBlockchainHelper(config.BlockchainInfos)
		lggr.Infow("Using real blockchain information from environment",
			"chainCount", len(config.BlockchainInfos))
		logBlockchainInfo(blockchainHelper, lggr)
		for _, selector := range blockchainHelper.GetAllChainSelectors() {
			lggr.Infow("Creating chain client", "chainSelector", selector)
			chainClients[selector] = pkg.CreateHealthyMultiNodeClient(ctx, blockchainHelper, lggr, selector)
		}
	}

	// Create source readers and head trackers - either blockchain-based or mock
	sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)

	// Try to create blockchain source readers if possible
	for _, selector := range blockchainHelper.GetAllChainSelectors() {
		lggr.Infow("Creating source reader", "chainSelector", selector, "strSelector", uint64(selector))
		strSelector := strconv.FormatUint(uint64(selector), 10)

		if config.OnRampAddresses[strSelector] == "" {
			lggr.Errorw("On ramp address is not set", "chainSelector", selector)
			continue
		}
		if config.RMNRemoteAddresses[strSelector] == "" {
			lggr.Errorw("RMN Remote address is not set", "chainSelector", selector)
			continue
		}

		// Create head tracker wrapper (uses hardcoded confirmation depth of 10 internally)
		// This is only for standalone mode and for testing purposes.
		// In CL node it'll be using HeadTracker which already abstracts away this per chain.
		headTracker := newSimpleHeadTrackerWrapper(chainClients[selector], lggr)

		evmSourceReader, err := sourcereader.NewEVMSourceReader(
			chainClients[selector],
			headTracker,
			common.HexToAddress(config.OnRampAddresses[strSelector]),
			common.HexToAddress(config.RMNRemoteAddresses[strSelector]),
			onramp.OnRampCCIPMessageSent{}.Topic().Hex(),
			selector,
			lggr,
		)
		if err != nil {
			lggr.Errorw("Failed to create EVM source reader", "selector", selector, "error", err)
			continue
		}

		// EVMSourceReader implements both SourceReader and HeadTracker interfaces
		sourceReaders[selector] = evmSourceReader

		lggr.Infow("Created blockchain source reader", "chain", selector)
	}

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

	// Start HTTP server
	httpServer := &http.Server{Addr: ":8100", ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go func() {
		lggr.Infow("🌐 HTTP server starting", "port", "8100")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			lggr.Errorw("HTTP server error", "error", err)
		}
	}()

	messageTracker := monitoring.NewMessageLatencyTracker(
		lggr,
		config.VerifierID,
		verifierMonitoring,
	)

	rmnRemoteAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.RMNRemoteAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Errorw("Failed to create RMN Remote address", "error", err, "selector", selector)
			os.Exit(1)
		}
		rmnRemoteAddresses[selector] = addr
	}

	offchainStorage := storage.NewOffchainStorage()

	coordinators := make([]*verifier.Coordinator, 0, len(config.TokenVerifiers))
	for _, verifierConfig := range config.TokenVerifiers {
		var coordinator *verifier.Coordinator
		if verifierConfig.IsCCTP() {
			coordinator = createLBTCCoordinator(
				config.VerifierID,
				verifierConfig.LBTC,
				lggr,
				sourceReaders,
				rmnRemoteAddresses,
				offchainStorage,
				messageTracker,
				verifierMonitoring,
			)
		} else if verifierConfig.IsCCTP() {
			coordinator = createCCTPCoordinator(
				config.VerifierID,
				verifierConfig.CCTP,
				lggr,
				sourceReaders,
				rmnRemoteAddresses,
				offchainStorage,
				messageTracker,
				verifierMonitoring,
			)
		} else {
			lggr.Fatalw("Unknown verifier type", "type", verifierConfig.Type)
			continue
		}

		if err := coordinator.Start(ctx); err != nil {
			lggr.Errorw("Failed to start verification coordinator", "error", err)
			os.Exit(1)
		}
	}

	lggr.Infow("🎯 Verifier service fully started and ready!")

	// Wait for shutdown signal
	<-sigCh
	lggr.Infow("🛑 Shutdown signal received, stopping verifier...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	for _, coordinator := range coordinators {
		if err := coordinator.Close(); err != nil {
			lggr.Errorw("Coordinator shutdown error", "error", err)
		}
	}
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		lggr.Errorw("HTTP server shutdown error", "error", err)
	}

	lggr.Infow("Verifier service stopped gracefully")
}

func createCCTPCoordinator(
	verifierID string,
	cctpConfig *cctp.Config,
	lggr logger.Logger,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	rmnRemoteAddresses map[string]protocol.UnknownAddress,
	offchainStorage *storage.OffchainStorage,
	messageTracker verifier.MessageLatencyTracker,
	verifierMonitoring verifier.Monitoring,
) *verifier.Coordinator {
	cctpSourceConfigs := createSourceConfigs(cctpConfig.Verifiers, rmnRemoteAddresses)

	cctpVerifier := cctp.NewVerifier(
		cctp.NewAttestationService(*cctpConfig),
	)

	cctpCoordinator, err := verifier.NewCoordinator(
		lggr,
		cctpVerifier,
		sourceReaders,
		offchainStorage,
		verifier.CoordinatorConfig{
			VerifierID:          verifierID,
			SourceConfigs:       cctpSourceConfigs,
			StorageBatchSize:    50,
			StorageBatchTimeout: 100 * time.Millisecond,
			CursePollInterval:   2 * time.Second,
		},
		messageTracker,
		verifierMonitoring,
		storage.NewChainStatusManager(),
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator for cctp", "error", err)
		os.Exit(1)
	}
	return cctpCoordinator
}

func createLBTCCoordinator(
	verifierID string,
	lbtcConfig *lbtc.Config,
	lggr logger.Logger,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	rmnRemoteAddresses map[string]protocol.UnknownAddress,
	offchainStorage *storage.OffchainStorage,
	messageTracker verifier.MessageLatencyTracker,
	verifierMonitoring verifier.Monitoring,
) *verifier.Coordinator {
	sourceConfigs := createSourceConfigs(lbtcConfig.Verifiers, rmnRemoteAddresses)

	lbtcVerifier := lbtc.NewVerifier(
		lbtc.NewAttestationService(*lbtcConfig),
	)

	lbtcCoordinator, err := verifier.NewCoordinator(
		lggr,
		lbtcVerifier,
		sourceReaders,
		offchainStorage,
		verifier.CoordinatorConfig{
			VerifierID:          verifierID,
			SourceConfigs:       sourceConfigs,
			StorageBatchSize:    50,
			StorageBatchTimeout: 100 * time.Millisecond,
			CursePollInterval:   2 * time.Second,
		},
		messageTracker,
		verifierMonitoring,
		storage.NewChainStatusManager(),
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator for lbtc", "error", err)
		os.Exit(1)
	}

	return lbtcCoordinator
}

func createSourceConfigs(
	verifiers map[protocol.ChainSelector]protocol.UnknownAddress,
	rmnRemoteAddresses map[string]protocol.UnknownAddress,
) map[protocol.ChainSelector]verifier.SourceConfig {
	sourceConfigs := make(map[protocol.ChainSelector]verifier.SourceConfig)
	for selector, address := range verifiers {
		strSelector := strconv.FormatUint(uint64(selector), 10)
		sourceConfigs[selector] = verifier.SourceConfig{
			VerifierAddress:        address,
			DefaultExecutorAddress: nil,
			PollInterval:           1 * time.Second,
			ChainSelector:          selector,
			RMNRemoteAddress:       rmnRemoteAddresses[strSelector],
		}
	}
	return sourceConfigs
}

// simpleHeadTrackerWrapper is a simple implementation that wraps chain client calls.
// This provides a HeadTracker interface without requiring the full EVM head tracker setup.
// It calculates finalized blocks using a hardcoded confirmation depth.
type simpleHeadTrackerWrapper struct {
	chainClient client.Client
	lggr        logger.Logger
}

// newSimpleHeadTrackerWrapper creates a new simple head tracker that delegates to the chain client.
func newSimpleHeadTrackerWrapper(chainClient client.Client, lggr logger.Logger) *simpleHeadTrackerWrapper {
	return &simpleHeadTrackerWrapper{
		chainClient: chainClient,
		lggr:        lggr,
	}
}

// LatestAndFinalizedBlock returns the latest and finalized block headers.
// Finalized is calculated as latest - verifier.ConfirmationDepth.
func (m *simpleHeadTrackerWrapper) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *evmtypes.Head, err error) {
	// Get latest block
	latestHead, err := m.chainClient.HeadByNumber(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get latest block: %w", err)
	}

	// Calculate finalized block number based on confirmation depth
	var finalizedBlockNum int64
	if latestHead.Number >= verifier.ConfirmationDepth {
		finalizedBlockNum = latestHead.Number - verifier.ConfirmationDepth
	} else {
		finalizedBlockNum = 0
	}

	// Get finalized block header
	finalizedHead, err := m.chainClient.HeadByNumber(ctx, big.NewInt(finalizedBlockNum))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get block at number %d: %w", finalizedBlockNum, err)
	}

	return latestHead, finalizedHead, nil
}

// LatestSafeBlock returns the latest safe block header.
// Returns nil if the chain doesn't support safe blocks (optional feature).
func (m *simpleHeadTrackerWrapper) LatestSafeBlock(ctx context.Context) (safe *evmtypes.Head, err error) {
	return nil, nil
}

// Backfill is a no-op for the mock implementation.
// In production, this would fetch historical blocks to fill gaps in the chain.
func (m *simpleHeadTrackerWrapper) Backfill(ctx context.Context, headWithChain, prevHeadWithChain *evmtypes.Head) error {
	// Mock implementation doesn't need backfill functionality
	return nil
}

// LatestChain returns the latest head.
// This is a synchronous call that returns the most recent block.
func (m *simpleHeadTrackerWrapper) LatestChain() *evmtypes.Head {
	return nil
}

// Start is a no-op for the mock implementation (implements services.Service).
func (m *simpleHeadTrackerWrapper) Start(ctx context.Context) error {
	return nil
}

// Close is a no-op for the mock implementation (implements services.Service).
func (m *simpleHeadTrackerWrapper) Close() error {
	return nil
}

// Name returns the service name (implements services.Service).
func (m *simpleHeadTrackerWrapper) Name() string {
	return "MockHeadTracker"
}

// Ready checks if the service is ready (implements services.Service).
func (m *simpleHeadTrackerWrapper) Ready() error {
	return nil
}

// HealthReport returns the health status (implements services.Service).
func (m *simpleHeadTrackerWrapper) HealthReport() map[string]error {
	return map[string]error{m.Name(): nil}
}
