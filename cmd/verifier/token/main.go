package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"go.uber.org/zap/zapcore"

	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/ccvstorage"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token"
	tokenapi "github.com/smartcontractkit/chainlink-ccv/verifier/token/api"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/lombard"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/storage"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	ConfigPath = "TOKEN_VERIFIER_CONFIG_PATH"
)

func main() {
	// Debug level currently spams a lot of logs from the RPC callers.
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}
	lggr = logger.Named(lggr, "verifier")

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
	config, blockchainInfos, err := loadConfiguration(filePath)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	cmd.StartPyroscope(lggr, config.PyroscopeURL, "tokenVerifier")
	blockchainHelper := cmd.LoadBlockchainInfo(ctx, lggr, blockchainInfos)

	registry := accessors.NewRegistry(blockchainHelper)
	cmd.RegisterEVM(ctx, registry, lggr, blockchainHelper, config.OnRampAddresses, config.RMNRemoteAddresses)

	sourceReaders := cmd.LoadBlockchainReadersForToken(ctx, lggr, registry, blockchainHelper, *config)

	verifierMonitoring := cmd.SetupMonitoring(lggr, config.Monitoring)

	rmnRemoteAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.RMNRemoteAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Errorw("Failed to create RMN Remote address", "error", err, "selector", selector)
			os.Exit(1)
		}
		rmnRemoteAddresses[selector] = addr
	}

	sqlDB, err := cmd.ConnectToPostgresDB(lggr)
	if err != nil {
		lggr.Errorw("Failed to connect to Postgres database", "error", err)
		os.Exit(1)
	}

	postgresStorage := ccvstorage.NewPostgres(sqlDB, lggr)
	// Wrap storage with monitoring decorator to track query durations
	monitoredStorage := ccvstorage.NewMonitoredStorage(postgresStorage, verifierMonitoring.Metrics())

	coordinators := make([]*verifier.Coordinator, 0, len(config.TokenVerifiers))
	for _, verifierConfig := range config.TokenVerifiers {
		chainStatusManager := chainstatus.NewPostgresChainStatusManager(sqlDB, lggr, verifierConfig.VerifierID)
		// Wrap chain status manager with monitoring decorator to track query durations
		monitoredChainStatusManager := chainstatus.NewMonitoredChainStatusManager(chainStatusManager, verifierMonitoring.Metrics())

		messageTracker := monitoring.NewMessageLatencyTracker(
			lggr,
			verifierConfig.VerifierID,
			verifierMonitoring,
		)

		var coordinator *verifier.Coordinator
		if verifierConfig.IsLombard() {
			coordinator = createLombardCoordinator(
				ctx,
				verifierConfig.VerifierID,
				verifierConfig.LombardConfig,
				lggr,
				sourceReaders,
				rmnRemoteAddresses,
				storage.NewAttestationCCVWriter(
					lggr,
					verifierConfig.LombardConfig.ParsedVerifierResolvers,
					monitoredStorage,
				),
				messageTracker,
				verifierMonitoring,
				monitoredChainStatusManager,
				sqlDB.DB,
			)
		} else if verifierConfig.IsCCTP() {
			coordinator = createCCTPCoordinator(
				ctx,
				verifierConfig.VerifierID,
				verifierConfig.CCTPConfig,
				lggr,
				sourceReaders,
				rmnRemoteAddresses,
				storage.NewAttestationCCVWriter(
					lggr,
					verifierConfig.CCTPConfig.ParsedVerifierResolvers,
					monitoredStorage,
				),
				messageTracker,
				verifierMonitoring,
				monitoredChainStatusManager,
				sqlDB.DB,
			)
		} else {
			lggr.Fatalw("Unknown verifier type", "type", verifierConfig.Type)
			continue
		}

		coordinators = append(coordinators, coordinator)

		if err := coordinator.Start(ctx); err != nil {
			lggr.Errorw("Failed to start verification coordinator", "error", err)
			os.Exit(1)
		}
	}

	healthReporters := make([]protocol.HealthReporter, len(coordinators))
	for i, coordinator := range coordinators {
		healthReporters[i] = coordinator
	}
	ginRouter := tokenapi.NewHTTPAPI(lggr, storage.NewAttestationCCVReader(postgresStorage), healthReporters, verifierMonitoring)

	// Start HTTP server with Gin router
	httpServer := &http.Server{
		Addr:         ":8100",
		Handler:      ginRouter,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		lggr.Infow("🌐 HTTP API server starting", "port", "8100")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		lggr.Errorw("HTTP server shutdown error", "error", err)
	}

	for _, coordinator := range coordinators {
		if err := coordinator.Close(); err != nil {
			lggr.Errorw("Coordinator shutdown error", "error", err)
		}
	}

	lggr.Infow("Token verifier service stopped gracefully")
}

func createCCTPCoordinator(
	ctx context.Context,
	verifierID string,
	cctpConfig *cctp.CCTPConfig,
	lggr logger.Logger,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	rmnRemoteAddresses map[string]protocol.UnknownAddress,
	ccvStorage protocol.CCVNodeDataWriter,
	messageTracker verifier.MessageLatencyTracker,
	verifierMonitoring verifier.Monitoring,
	chainStatusManager protocol.ChainStatusManager,
	db *sql.DB,
) *verifier.Coordinator {
	cctpSourceConfigs := createSourceConfigs(cctpConfig.ParsedVerifierResolvers, rmnRemoteAddresses)

	attestationService, err := cctp.NewAttestationService(lggr, *cctpConfig)
	if err != nil {
		lggr.Errorw("Failed to create CCTP attestation service", "error", err)
		os.Exit(1)
	}

	coordinator, err := verifier.NewCoordinator(
		ctx,
		lggr,
		cctp.NewVerifier(lggr, attestationService),
		sourceReaders,
		ccvStorage,
		verifier.CoordinatorConfig{
			VerifierID:          verifierID,
			SourceConfigs:       cctpSourceConfigs,
			StorageBatchSize:    50,
			StorageBatchTimeout: 100 * time.Millisecond,
			// In this case it's a database so we can do more aggressive retries
			StorageRetryDelay: 500 * time.Millisecond,
			CursePollInterval: 2 * time.Second,
		},
		messageTracker,
		verifierMonitoring,
		chainStatusManager,
		heartbeatclient.NewNoopHeartbeatClient(),
		db,
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator for cctp", "error", err)
		os.Exit(1)
	}
	return coordinator
}

func createLombardCoordinator(
	ctx context.Context,
	verifierID string,
	lombardConfig *lombard.LombardConfig,
	lggr logger.Logger,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	rmnRemoteAddresses map[string]protocol.UnknownAddress,
	ccvStorage protocol.CCVNodeDataWriter,
	messageTracker verifier.MessageLatencyTracker,
	verifierMonitoring verifier.Monitoring,
	chainStatusManager protocol.ChainStatusManager,
	db *sql.DB,
) *verifier.Coordinator {
	sourceConfigs := createSourceConfigs(lombardConfig.ParsedVerifierResolvers, rmnRemoteAddresses)

	attestationService, err := lombard.NewAttestationService(lggr, *lombardConfig)
	if err != nil {
		lggr.Errorw("Failed to create Lombard attestation service", "error", err)
		os.Exit(1)
	}

	lombardVerifier, err := lombard.NewVerifier(lggr, *lombardConfig, attestationService)
	if err != nil {
		lggr.Errorw("Failed to create Lombard verifier", "error", err)
		os.Exit(1)
	}

	coordinator, err := verifier.NewCoordinator(
		ctx,
		lggr,
		lombardVerifier,
		sourceReaders,
		ccvStorage,
		verifier.CoordinatorConfig{
			VerifierID:          verifierID,
			SourceConfigs:       sourceConfigs,
			StorageBatchSize:    50,
			StorageBatchTimeout: 100 * time.Millisecond,
			// In this case it's a database so we can do more aggressive retries
			StorageRetryDelay: 500 * time.Millisecond,
			CursePollInterval: 2 * time.Second,
		},
		messageTracker,
		verifierMonitoring,
		chainStatusManager,
		heartbeatclient.NewNoopHeartbeatClient(),
		db,
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator for lombard", "error", err)
		os.Exit(1)
	}

	return coordinator
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

func loadConfiguration(filepath string) (*token.Config, map[string]*blockchain.Info, error) {
	var config token.ConfigWithBlockchainInfos
	if _, err := toml.DecodeFile(filepath, &config); err != nil {
		return nil, nil, err
	}
	return &config.Config, config.BlockchainInfos, nil
}
