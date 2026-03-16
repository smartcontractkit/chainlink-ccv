package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"

	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors"
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

type tokenVerifierFactory struct {
	bootstrap.ServiceFactory[token.Config]

	coordinators []*verifier.Coordinator
	httpServer   *http.Server
	lggr         logger.Logger
}

// Stop tries to stop all services gracefully.
func (tvf *tokenVerifierFactory) Stop(ctx context.Context) error {
	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	var errs []error
	if err := tvf.httpServer.Shutdown(shutdownCtx); err != nil {
		tvf.lggr.Errorw("HTTP server shutdown error", "error", err)
		errs = append(errs, fmt.Errorf("HTTP server shutdown error: %w", err))
	}

	for _, coordinator := range tvf.coordinators {
		if err := coordinator.Close(); err != nil {
			tvf.lggr.Errorw("Coordinator shutdown error", "error", err)
			errs = append(errs, fmt.Errorf("coordinator shutdown error: %w", err))
		}
	}

	tvf.lggr.Infow("Token verifier service stopped gracefully")

	return errors.Join(errs...)
}

// Start starts the service with the parsed config received from the bootstrapper.
func (tvf *tokenVerifierFactory) Start(ctx context.Context, appConfig token.ConfigWithBlockchainInfos, deps bootstrap.ServiceDeps) error {
	logLevelStr := os.Getenv("LOG_LEVEL")
	if logLevelStr == "" {
		logLevelStr = "info"
	}
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(logLevelStr)); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Invalid LOG_LEVEL '%s', defaulting to 'info'\n", logLevelStr)
		zapLevel = zapcore.InfoLevel
	}
	var err error
	tvf.lggr, err = logger.NewWith(logging.DevelopmentConfig(zapLevel))
	if err != nil {
		return fmt.Errorf("failed to create logger: %v", err)
	}
	tvf.lggr = logger.Named(tvf.lggr, "verifier")

	// Use SugaredLogger for better API
	tvf.lggr = logger.Sugared(tvf.lggr)

	// TODO: validate config?
	config := appConfig.Config
	blockchainInfos := appConfig.BlockchainInfos

	_, err = cmd.StartPyroscope(tvf.lggr, config.PyroscopeURL, "tokenVerifier")
	if err != nil {
		tvf.lggr.Errorw("Failed to start pyroscope", "error", err)
		os.Exit(1)
	}
	blockchainHelper := cmd.LoadBlockchainInfo(ctx, tvf.lggr, blockchainInfos)

	registry := accessors.NewRegistry(blockchainHelper)
	cmd.RegisterEVM(ctx, registry, tvf.lggr, blockchainHelper, config.OnRampAddresses, config.RMNRemoteAddresses)

	sourceReaders := cmd.LoadBlockchainReadersForToken(ctx, tvf.lggr, registry, blockchainHelper, config)

	verifierMonitoring := cmd.SetupMonitoring(tvf.lggr, config.Monitoring, "token_verifier")

	rmnRemoteAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.RMNRemoteAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			tvf.lggr.Errorw("Failed to create RMN Remote address", "error", err, "selector", selector)
			os.Exit(1)
		}
		rmnRemoteAddresses[selector] = addr
	}

	db, err := cmd.ConnectToPostgresDB(tvf.lggr)
	if err != nil {
		tvf.lggr.Errorw("Failed to connect to Postgres database", "error", err)
		os.Exit(1)
	}

	postgresStorage := ccvstorage.NewPostgres(db, tvf.lggr)
	// Wrap storage with monitoring decorator to track query durations
	monitoredStorage := ccvstorage.NewMonitoredStorage(postgresStorage, verifierMonitoring.Metrics())

	// save the coordinators so that they can be shutdown later on.
	tvf.coordinators = make([]*verifier.Coordinator, 0, len(config.TokenVerifiers))
	for _, verifierConfig := range config.TokenVerifiers {
		chainStatusManager := chainstatus.NewPostgresChainStatusManager(db, tvf.lggr, verifierConfig.VerifierID)
		// Wrap chain status manager with monitoring decorator to track query durations
		monitoredChainStatusManager := chainstatus.NewMonitoredChainStatusManager(chainStatusManager, verifierMonitoring.Metrics())

		messageTracker := monitoring.NewMessageLatencyTracker(
			tvf.lggr,
			verifierConfig.VerifierID,
			verifierMonitoring,
		)

		var coordinator *verifier.Coordinator
		if verifierConfig.IsLombard() {
			coordinator = createLombardCoordinator(
				ctx,
				verifierConfig.VerifierID,
				verifierConfig.LombardConfig,
				tvf.lggr,
				sourceReaders,
				rmnRemoteAddresses,
				storage.NewAttestationCCVWriter(
					tvf.lggr,
					verifierConfig.LombardConfig.ParsedVerifierResolvers,
					monitoredStorage,
				),
				messageTracker,
				verifierMonitoring,
				monitoredChainStatusManager,
				db,
			)
		} else if verifierConfig.IsCCTP() {
			coordinator = createCCTPCoordinator(
				ctx,
				verifierConfig.VerifierID,
				verifierConfig.CCTPConfig,
				tvf.lggr,
				sourceReaders,
				rmnRemoteAddresses,
				storage.NewAttestationCCVWriter(
					tvf.lggr,
					verifierConfig.CCTPConfig.ParsedVerifierResolvers,
					monitoredStorage,
				),
				messageTracker,
				verifierMonitoring,
				monitoredChainStatusManager,
				db,
			)
		} else {
			tvf.lggr.Fatalw("Unknown verifier type", "type", verifierConfig.Type)
			continue
		}

		tvf.coordinators = append(tvf.coordinators, coordinator)

		if err := coordinator.Start(ctx); err != nil {
			tvf.lggr.Errorw("Failed to start verification coordinator", "error", err)
			return fmt.Errorf("failed to start verification coordinator: %w", err)
		}
	}

	healthReporters := make([]protocol.HealthReporter, len(tvf.coordinators))
	for i, coordinator := range tvf.coordinators {
		healthReporters[i] = coordinator
	}
	ginRouter := tokenapi.NewHTTPAPI(tvf.lggr, storage.NewAttestationCCVReader(postgresStorage), healthReporters, verifierMonitoring)

	// Start HTTP server with Gin router
	tvf.httpServer = &http.Server{
		Addr:         ":8100",
		Handler:      ginRouter,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		tvf.lggr.Infow("🌐 HTTP API server starting", "port", "8100")
		if err := tvf.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// TODO: how to register an error with the bootstrapper?
			tvf.lggr.Errorw("HTTP server error", "error", err)
		}
	}()

	tvf.lggr.Infow("🎯 Verifier service fully started and ready!")

	return nil
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
	db sqlutil.DataSource,
) *verifier.Coordinator {
	cctpSourceConfigs := createSourceConfigs(cctpConfig.ParsedVerifierResolvers, rmnRemoteAddresses)

	attestationService, err := cctp.NewAttestationService(lggr, *cctpConfig)
	if err != nil {
		lggr.Errorw("Failed to create CCTP attestation service", "error", err)
		os.Exit(1)
	}

	coordinator, err := verifier.NewCoordinator(
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
	db sqlutil.DataSource,
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
