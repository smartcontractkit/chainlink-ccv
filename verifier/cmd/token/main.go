package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"

	"go.uber.org/zap/zapcore"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	cmd "github.com/smartcontractkit/chainlink-ccv/verifier/cmd"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
	tokenapi "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/api"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/lombard"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "ccv" {
		cmd.RunCCVCLI(os.Args[1:])
		return
	}
	configPath := os.Getenv("TOKEN_VERIFIER_CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/config.toml"
	}

	err := bootstrap.Run(
		"TokenVerifier",
		&tokenVerifierFactory[evm.Info]{
			supportedChainFamily:      []string{chainsel.FamilyEVM},
			createAccessorFactoryFunc: evm.CreateAccessorFactory,
		},
		// TODO: remove the AppConfig generic type to streamline this API, update factory to accept config as a string.
		bootstrap.WithTOMLAppConfig[token.ConfigWithBlockchainInfos[evm.Info]](configPath),
	)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to run token verifier: %v\n", err)
		os.Exit(1)
	}
}

type tokenVerifierFactory[T any] struct {
	bootstrap.ServiceFactory[token.Config]

	// TODO: rather than creating the factory in the bootstrap layer, can we pass in a registry?
	createAccessorFactoryFunc accessors.CreateAccessorFactory[T]
	// TODO: This no longer makes sense because 'CreateAccessorFactory' only supports one family.
	supportedChainFamily []string

	coordinators []*verifier.Coordinator
	httpServer   *http.Server
	lggr         logger.Logger
}

// Stop tries to stop all services gracefully.
func (tvf *tokenVerifierFactory[T]) Stop(ctx context.Context) error {
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
func (tvf *tokenVerifierFactory[T]) Start(ctx context.Context, appConfig token.ConfigWithBlockchainInfos[T], deps bootstrap.ServiceDeps) error {
	var errs []error
	if tvf.createAccessorFactoryFunc == nil {
		errs = append(errs, fmt.Errorf("createAccessorFactoryFunc is required but was nil"))
	}
	if len(tvf.supportedChainFamily) == 0 {
		errs = append(errs, fmt.Errorf("at least one supportedChainFamily is required but was empty"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	// TODO: Add "WithLogLevelFromEnv" option and use deps.lggr.
	{
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
	}

	// Use SugaredLogger for better API
	tvf.lggr = logger.Sugared(tvf.lggr)

	protocol.InitChainSelectorCache()

	// TODO: validate config?
	config := appConfig.Config
	blockchainInfos := appConfig.BlockchainInfos

	_, err := cmd.StartPyroscope(tvf.lggr, config.PyroscopeURL, "tokenVerifier")
	if err != nil {
		tvf.lggr.Errorw("Failed to start pyroscope", "error", err)
		os.Exit(1)
	}

	factory, err := tvf.createAccessorFactoryFunc(ctx, tvf.lggr, blockchainInfos, config.OnRampAddresses, config.RMNRemoteAddresses)
	if err != nil {
		tvf.lggr.Errorw("Failed to create accessor factory", "error", err)
		return fmt.Errorf("failed to create accessor factory: %w", err)
	}

	// Initialize source readers from factory.
	blockchainHelper := cmd.LoadBlockchainInfo(ctx, tvf.lggr, blockchainInfos)
	sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)
	for _, selector := range blockchainHelper.GetAllChainSelectors() {
		fam, err := chainsel.GetSelectorFamily(uint64(selector))
		if err != nil {
			tvf.lggr.Errorw("Skipping chain, failed to get blockchain family for chain selector", "error", err, "chainSelector", selector)
			continue
		}
		if !slices.Contains(tvf.supportedChainFamily, fam) {
			tvf.lggr.Infow("Skipping chain, unsupported blockchain family", "chainSelector", selector, "family", fam)
			continue
		}
		accessor, err := factory.GetAccessor(ctx, selector)
		if err != nil {
			tvf.lggr.Errorw("Skipping chain, failed to get accessor for chain selector", "error", err, "chainSelector", selector)
			continue
		}
		if accessor.SourceReader() == nil {
			tvf.lggr.Errorw("Skipping chain, failed to get source reader for chain selector", "chainSelector", selector)
			continue
		}
		sourceReaders[selector] = accessor.SourceReader()
		tvf.lggr.Infow("Created source reader for chain", "chainSelector", selector)
	}

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

	postgresStorage := storage.NewPostgres(db, tvf.lggr)
	// Wrap storage with monitoring decorator to track query durations
	monitoredStorage := storage.NewMonitoredStorage(postgresStorage, verifierMonitoring.Metrics())

	// save the coordinators so that they can be shutdown later on.
	chainStatusStore := chainstatus.NewPostgresChainStatusStore(db, tvf.lggr)
	tvf.coordinators = make([]*verifier.Coordinator, 0, len(config.TokenVerifiers))
	for _, verifierConfig := range config.TokenVerifiers {
		chainStatusManager := chainstatus.NewPostgresChainStatusManager(chainStatusStore, verifierConfig.VerifierID)
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
				storage.NewCCVWriter(
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
				storage.NewCCVWriter(
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
	ginRouter := tokenapi.NewHTTPAPI(tvf.lggr, storage.NewCCVReader(postgresStorage), healthReporters, verifierMonitoring)
	verifierMonitoring.RecordServiceStarted(ctx)

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
