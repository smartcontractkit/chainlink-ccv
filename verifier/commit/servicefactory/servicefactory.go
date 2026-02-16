// package servicefactory implements the ServiceFactory interface for the commit verifier.
package servicefactory

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/grafana/pyroscope-go"
	"github.com/jmoiron/sqlx"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors"
	cantonaccessor "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/canton"
	evmaccessor "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader/canton"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/db"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
)

var _ bootstrap.ServiceFactory = &factory{}

type factory struct {
	lggr logger.Logger

	server           *http.Server
	coordinator      *verifier.Coordinator
	profiler         *pyroscope.Profiler
	aggregatorWriter *storageaccess.AggregatorWriter
	heartbeatClient  *heartbeatclient.HeartbeatClient
}

func New() bootstrap.ServiceFactory {
	return &factory{}
}

// Start implements [bootstrap.ServiceFactory].
func (f *factory) Start(ctx context.Context, spec string, deps bootstrap.ServiceDeps) error {
	lggr := logger.Sugared(logger.Named(deps.Logger, "CommitteeVerifier"))
	f.lggr = lggr

	config, blockchainInfos, err := loadConfiguration(spec)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "error", err)
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// TODO: this should be passed in via the config maybe?
	apiKey := os.Getenv("VERIFIER_AGGREGATOR_API_KEY")
	if apiKey == "" {
		lggr.Errorw("VERIFIER_AGGREGATOR_API_KEY environment variable is required")
		return fmt.Errorf("VERIFIER_AGGREGATOR_API_KEY environment variable is required")
	}
	if err := hmac.ValidateAPIKey(apiKey); err != nil {
		lggr.Errorw("Invalid VERIFIER_AGGREGATOR_API_KEY", "error", err)
		return fmt.Errorf("invalid VERIFIER_AGGREGATOR_API_KEY: %w", err)
	}
	lggr.Infow("Loaded VERIFIER_AGGREGATOR_API_KEY from environment")

	// TODO: this should be passed in via the config maybe?
	secretKey := os.Getenv("VERIFIER_AGGREGATOR_SECRET_KEY")
	if secretKey == "" {
		lggr.Errorw("VERIFIER_AGGREGATOR_SECRET_KEY environment variable is required")
		return fmt.Errorf("VERIFIER_AGGREGATOR_SECRET_KEY environment variable is required")
	}
	if err := hmac.ValidateSecret(secretKey); err != nil {
		lggr.Errorw("Invalid VERIFIER_AGGREGATOR_SECRET_KEY", "error", err)
		return fmt.Errorf("invalid VERIFIER_AGGREGATOR_SECRET_KEY: %w", err)
	}
	lggr.Infow("Loaded VERIFIER_AGGREGATOR_SECRET_KEY from environment")

	profiler, err := startPyroscope(lggr, config.PyroscopeURL, "verifier")
	if err != nil {
		lggr.Errorw("Failed to start pyroscope", "error", err)
		return fmt.Errorf("failed to start pyroscope: %w", err)
	}
	f.profiler = profiler

	blockchainHelper := loadBlockchainInfo(ctx, lggr, blockchainInfos)

	// Create verifier addresses before source readers setup
	verifierAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.CommitteeVerifierAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Errorw("Failed to create verifier address", "error", err)
			return fmt.Errorf("failed to create verifier address: %w", err)
		}
		verifierAddresses[selector] = addr
	}
	defaultExecutorAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.DefaultExecutorOnRampAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Errorw("Failed to create default executor address", "error", err)
			return fmt.Errorf("failed to create default executor address: %w", err)
		}
		defaultExecutorAddresses[selector] = addr
	}

	hmacConfig := &hmac.ClientConfig{
		APIKey: apiKey,
		Secret: secretKey,
	}

	aggregatorWriter, err := storageaccess.NewAggregatorWriter(config.AggregatorAddress, lggr, hmacConfig, config.InsecureAggregatorConnection)
	if err != nil {
		lggr.Errorw("Failed to create aggregator writer", "error", err)
		return fmt.Errorf("failed to create aggregator writer: %w", err)
	}

	f.aggregatorWriter = aggregatorWriter

	registry := accessors.NewRegistry(blockchainHelper)
	// TODO: if we're running one family per app, don't need to register all families.
	registerEVM(ctx, registry, lggr, blockchainHelper, config.OnRampAddresses, config.RMNRemoteAddresses)
	registerCanton(ctx, registry, lggr, blockchainHelper, config.CantonConfigs)

	sourceReaders, err := createSourceReaders(ctx, lggr, registry, blockchainHelper, *config)
	if err != nil {
		lggr.Errorw("Failed to create source readers", "error", err)
		return fmt.Errorf("failed to create source readers: %w", err)
	}

	// Create coordinator configuration
	sourceConfigs := make(map[protocol.ChainSelector]verifier.SourceConfig)
	rmnRemoteAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.RMNRemoteAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Errorw("Failed to create RMN Remote address", "error", err, "selector", selector)
			return fmt.Errorf("failed to create RMN Remote address: %w", err)
		}
		rmnRemoteAddresses[selector] = addr
	}

	for _, selector := range blockchainHelper.GetAllChainSelectors() {
		strSelector := strconv.FormatUint(uint64(selector), 10)

		sourceConfigs[selector] = verifier.SourceConfig{
			VerifierAddress:        verifierAddresses[strSelector],
			DefaultExecutorAddress: defaultExecutorAddresses[strSelector],
			PollInterval:           1 * time.Second,
			ChainSelector:          selector,
			RMNRemoteAddress:       rmnRemoteAddresses[strSelector],
			DisableFinalityChecker: slices.Contains(config.DisableFinalityCheckers, strSelector),
		}

		lggr.Infow("Configured source chain", "chainSelector", selector)
	}

	coordinatorConfig := verifier.CoordinatorConfig{
		VerifierID:          config.VerifierID,
		SourceConfigs:       sourceConfigs,
		StorageBatchSize:    50,
		StorageBatchTimeout: 100 * time.Millisecond,
		StorageRetryDelay:   2 * time.Second,
		CursePollInterval:   2 * time.Second,  // Poll RMN Remotes for curse status every 2s
		HeartbeatInterval:   10 * time.Second, // Send heartbeat to aggregator every 10s
	}

	signer, _, signerAddress, err := commit.NewECDSAKeystoreSigner(deps.Keystore, bootstrap.DefaultECDSASigningKeyName)
	if err != nil {
		lggr.Errorw("Failed to create signer", "error", err)
		return fmt.Errorf("failed to create signer: %w", err)
	}
	lggr.Infow("Using signer address", "address", signerAddress)

	verifierMonitoring := setupMonitoring(lggr, config.Monitoring)

	// Create chain status manager (PostgreSQL storage) with monitoring decorator
	chainStatusManager, chainStatusDB, err := createChainStatusManager(lggr, config.VerifierID, verifierMonitoring)
	if err != nil {
		lggr.Errorw("Failed to create chain status manager", "error", err)
		return fmt.Errorf("failed to create chain status manager: %w", err)
	}
	defer func() {
		if chainStatusDB != nil {
			_ = chainStatusDB.Close()
		}
	}()

	// Create commit verifier
	commitVerifier, err := commit.NewCommitVerifier(coordinatorConfig, signerAddress, signer, lggr, verifierMonitoring)
	if err != nil {
		lggr.Errorw("Failed to create commit verifier", "error", err)
		return fmt.Errorf("failed to create commit verifier: %w", err)
	}

	observedStorageWriter := storageaccess.NewObservedStorageWriter(
		storageaccess.NewDefaultResilientStorageWriter(
			aggregatorWriter,
			lggr,
		),
		config.VerifierID,
		lggr,
		verifierMonitoring,
	)

	heartbeatClient, err := heartbeatclient.NewHeartbeatClient(
		config.AggregatorAddress,
		lggr,
		hmacConfig,
		config.InsecureAggregatorConnection,
	)
	if err != nil {
		lggr.Errorw("Failed to create heartbeat client", "error", err)
		return fmt.Errorf("failed to create heartbeat client: %w", err)
	}

	f.heartbeatClient = heartbeatClient

	observedHeartbeatClient := heartbeatclient.NewObservedHeartbeatClient(
		heartbeatClient,
		config.VerifierID,
		lggr,
		verifier.NewHeartbeatMonitoringAdapter(verifierMonitoring),
	)

	messageTracker := monitoring.NewMessageLatencyTracker(
		lggr,
		config.VerifierID,
		verifierMonitoring,
	)

	// Create verification coordinator
	coordinator, err := verifier.NewCoordinator(
		ctx,
		lggr,
		commitVerifier,
		sourceReaders,
		observedStorageWriter,
		coordinatorConfig,
		messageTracker,
		verifierMonitoring,
		chainStatusManager,
		observedHeartbeatClient,
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator", "error", err)
		return fmt.Errorf("failed to create verification coordinator: %w", err)
	}

	// Start the verification coordinator
	lggr.Infow("Starting Verification Coordinator",
		"verifierID", coordinatorConfig.VerifierID,
		"verifierAddress", verifierAddresses,
	)

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Failed to start verification coordinator", "error", err)
		return fmt.Errorf("failed to start verification coordinator: %w", err)
	}

	// Setup HTTP server for health checks and status
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		lggr.Infow("CCV Verifier is running!\n")
		lggr.Infow("Verifier ID: %s\n", coordinatorConfig.VerifierID)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		for serviceName, err := range coordinator.HealthReport() {
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				lggr.Infow("Unhealthy service: %s, error: %s\n", serviceName, err.Error())
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		lggr.Infow("Healthy\n")
	})

	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := aggregatorWriter.GetStats()
		lggr.Infow("Storage Statistics:\n")
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

	f.server = server
	f.coordinator = coordinator

	lggr.Infow("🎯 Verifier service fully started and ready!")

	return nil
}

// Stop implements [bootstrap.ServiceFactory].
func (f *factory) Stop(ctx context.Context) error {
	// Stop HTTP server
	if err := f.server.Shutdown(ctx); err != nil {
		f.lggr.Errorw("HTTP server shutdown error", "error", err)
	}

	// Stop verification coordinator
	if err := f.coordinator.Close(); err != nil {
		f.lggr.Errorw("Coordinator stop error", "error", err)
	}

	// Stop pyroscope
	if err := f.profiler.Stop(); err != nil {
		f.lggr.Errorw("Pyroscope stop error", "error", err)
	}

	// Stop aggregator writer
	// TODO: is this stopped by the coordinator?
	if err := f.aggregatorWriter.Close(); err != nil {
		f.lggr.Errorw("Aggregator writer stop error", "error", err)
	}

	// Stop heartbeat client
	if err := f.heartbeatClient.Close(); err != nil {
		f.lggr.Errorw("Heartbeat client stop error", "error", err)
	}

	// TODO: chain status db, is it closed by the coordinator?

	return nil
}

func loadConfiguration(spec string) (*commit.Config, map[string]*blockchain.Info, error) {
	var config commit.ConfigWithBlockchainInfos
	if _, err := toml.Decode(spec, &config); err != nil {
		return nil, nil, fmt.Errorf("failed to decode specification: %w", err)
	}
	return &config.Config, config.BlockchainInfos, nil
}

func createChainStatusManager(lggr logger.Logger, verifierID string, monitoring verifier.Monitoring) (protocol.ChainStatusManager, *sqlx.DB, error) {
	sqlDB, err := connectToPostgresDB(lggr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to Postgres DB: %w", err)
	}
	chainStatusManager := chainstatus.NewPostgresChainStatusManager(sqlDB, lggr, verifierID)
	// Wrap with monitoring decorator to track query durations
	monitoredManager := chainstatus.NewMonitoredChainStatusManager(chainStatusManager, monitoring.Metrics())
	return monitoredManager, sqlDB, nil
}

const (
	// Database environment variables.
	DatabaseURLEnvVar             = "CL_DATABASE_URL"
	DatabaseMaxOpenConnsEnvVar    = "CL_DATABASE_MAX_OPEN_CONNS"
	DatabaseMaxIdleConnsEnvVar    = "CL_DATABASE_MAX_IDLE_CONNS"
	DatabaseConnMaxLifetimeEnvVar = "CL_DATABASE_CONN_MAX_LIFETIME"
	DatabaseConnMaxIdleTimeEnvVar = "CL_DATABASE_CONN_MAX_IDLE_TIME"

	// Database defaults.
	defaultMaxOpenConns    = 20
	defaultMaxIdleConns    = 10
	defaultConnMaxLifetime = 300 // seconds
	defaultConnMaxIdleTime = 60  // seconds
)

func getEnvInt(key string, defaultValue int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	intVal, err := strconv.Atoi(val)
	if err != nil {
		return defaultValue
	}
	return intVal
}

func connectToPostgresDB(lggr logger.Logger) (*sqlx.DB, error) {
	dbURL := os.Getenv(DatabaseURLEnvVar)
	if dbURL == "" {
		return nil, nil
	}

	maxOpenConns := getEnvInt(DatabaseMaxOpenConnsEnvVar, defaultMaxOpenConns)
	maxIdleConns := getEnvInt(DatabaseMaxIdleConnsEnvVar, defaultMaxIdleConns)
	connMaxLifetime := getEnvInt(DatabaseConnMaxLifetimeEnvVar, defaultConnMaxLifetime)
	connMaxIdleTime := getEnvInt(DatabaseConnMaxIdleTimeEnvVar, defaultConnMaxIdleTime)

	dbx, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, nil
	}

	dbx.SetMaxOpenConns(maxOpenConns)
	dbx.SetMaxIdleConns(maxIdleConns)
	dbx.SetConnMaxLifetime(time.Duration(connMaxLifetime) * time.Second)
	dbx.SetConnMaxIdleTime(time.Duration(connMaxIdleTime) * time.Second)

	if err := ccvcommon.EnsureDBConnection(lggr, dbx); err != nil {
		_ = dbx.Close()
		return nil, fmt.Errorf("failed to ping postgres database: %w", err)
	}

	sqlxDB := sqlx.NewDb(dbx, "postgres")

	if err := db.RunPostgresMigrations(sqlxDB); err != nil {
		_ = dbx.Close()
		return nil, fmt.Errorf("failed to run postgres migrations: %w", err)
	}

	lggr.Infow("Using PostgreSQL chain status storage",
		"maxOpenConns", maxOpenConns,
		"maxIdleConns", maxIdleConns,
		"connMaxLifetime", connMaxLifetime,
		"connMaxIdleTime", connMaxIdleTime,
	)

	return sqlxDB, nil
}

func startPyroscope(lggr logger.Logger, pyroscopeAddress, serviceName string) (*pyroscope.Profiler, error) {
	profiler, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: serviceName,
		ServerAddress:   pyroscopeAddress,
		Logger:          nil, // Disable pyroscope logging - so noisy
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileBlockDuration,
			pyroscope.ProfileMutexDuration,
		},
	})
	if err != nil {
		lggr.Errorw("Failed to start pyroscope", "error", err)
		return nil, fmt.Errorf("failed to start pyroscope: %w", err)
	}
	return profiler, nil
}

func loadBlockchainInfo(
	ctx context.Context,
	lggr logger.Logger,
	config map[string]*blockchain.Info,
) *blockchain.Helper {
	// Use actual blockchain information from configuration
	if len(config) == 0 {
		lggr.Warnw("No blockchain information in config")
		return nil
	}
	blockchainHelper := blockchain.NewHelper(config)
	lggr.Infow("Using real blockchain information from environment",
		"chainCount", len(config))
	logBlockchainInfo(blockchainHelper, lggr)
	return blockchainHelper
}

func logBlockchainInfo(blockchainHelper *blockchain.Helper, lggr logger.Logger) {
	for _, chainID := range blockchainHelper.GetAllChainSelectors() {
		logChainInfo(blockchainHelper, chainID, lggr)
	}
}

func logChainInfo(blockchainHelper *blockchain.Helper, chainSelector protocol.ChainSelector, lggr logger.Logger) {
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

func registerEVM(ctx context.Context, registry *accessors.Registry, lggr logger.Logger, helper *blockchain.Helper, onRampAddresses, rmnRemoteAddresses map[string]string) {
	// Create the chain clients then the head trackers
	chainClients := make(map[protocol.ChainSelector]client.Client)
	for _, selector := range helper.GetAllChainSelectors() {
		family, err := chainsel.GetSelectorFamily(uint64(selector))
		if err != nil {
			lggr.Errorw("❌ Failed to get selector family - update chain-selectors library?", "chainSelector", selector, "error", err)
			continue
		}
		if family != chainsel.FamilyEVM {
			// Skip non-EVM chains in EVM registration.
			continue
		}
		chainClient := pkg.CreateHealthyMultiNodeClient(ctx, helper, lggr, selector)
		chainClients[selector] = chainClient
	}

	headTrackers := make(map[protocol.ChainSelector]heads.Tracker)
	for _, selector := range helper.GetAllChainSelectors() {
		family, err := chainsel.GetSelectorFamily(uint64(selector))
		if err != nil {
			lggr.Errorw("❌ Failed to get selector family - update chain-selectors library?", "chainSelector", selector, "error", err)
			continue
		}
		if family != chainsel.FamilyEVM {
			// Skip non-EVM chains in EVM registration.
			continue
		}
		headTracker := sourcereader.NewSimpleHeadTrackerWrapper(chainClients[selector], lggr)
		headTrackers[selector] = headTracker
	}

	registry.Register(chainsel.FamilyEVM, evmaccessor.NewFactory(lggr, helper, onRampAddresses, rmnRemoteAddresses, headTrackers, chainClients))
}

func registerCanton(ctx context.Context, registry *accessors.Registry, lggr logger.Logger, helper *blockchain.Helper, cantonConfigs map[string]commit.CantonConfig) {
	readerConfigs := make(map[string]canton.ReaderConfig)
	for selector, config := range cantonConfigs {
		readerConfigs[selector] = config.ReaderConfig
	}
	registry.Register(chainsel.FamilyCanton, cantonaccessor.NewFactory(lggr, helper, readerConfigs))
}

func createSourceReaders(
	ctx context.Context,
	lggr logger.Logger,
	registry *accessors.Registry,
	helper *blockchain.Helper,
	config commit.Config,
) (map[protocol.ChainSelector]chainaccess.SourceReader, error) {
	readers := make(map[protocol.ChainSelector]chainaccess.SourceReader)
	for _, selector := range helper.GetAllChainSelectors() {
		accessor, err := registry.GetAccessor(ctx, selector)
		if err != nil {
			lggr.Errorw("❌ Failed to create source reader", "chainSelector", selector, "error", err)
			continue
		}

		reader := accessor.SourceReader()
		if reader == nil {
			lggr.Errorw("❌ Failed to get source reader for chain", "chainSelector", selector)
			continue
		}

		readers[selector] = reader
		lggr.Infow("🚀 Created source reader for chain", "chainSelector", selector)
	}
	return readers, nil
}

func setupMonitoring(lggr logger.Logger, config verifier.MonitoringConfig) verifier.Monitoring {
	beholderConfig := beholder.Config{
		InsecureConnection:       config.Beholder.InsecureConnection,
		CACertFile:               config.Beholder.CACertFile,
		OtelExporterHTTPEndpoint: config.Beholder.OtelExporterHTTPEndpoint,
		OtelExporterGRPCEndpoint: config.Beholder.OtelExporterGRPCEndpoint,
		LogStreamingEnabled:      config.Beholder.LogStreamingEnabled,
		MetricReaderInterval:     time.Second * time.Duration(config.Beholder.MetricReaderInterval),
		TraceSampleRatio:         config.Beholder.TraceSampleRatio,
		TraceBatchTimeout:        time.Second * time.Duration(config.Beholder.TraceBatchTimeout),
		// Note: due to OTEL spec, all histogram buckets must be defined when the beholder client is created.
		MetricViews: monitoring.MetricViews(),
	}

	// Create the beholder client
	beholderClient, err := beholder.NewClient(beholderConfig)
	if err != nil {
		lggr.Fatalf("failed to create beholder client: %w", err)
	}

	// Set the beholder client and global otel providers
	beholder.SetClient(beholderClient)
	beholder.SetGlobalOtelProviders()
	verifierMonitoring, err := monitoring.InitMonitoring()
	if err != nil {
		lggr.Fatalf("Failed to initialize verifier monitoring: %w", err)
	}
	return verifierMonitoring
}
