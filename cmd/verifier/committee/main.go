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
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"go.uber.org/zap/zapcore"

	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	PkEnvVar   = "VERIFIER_SIGNER_PRIVATE_KEY"
	ConfigPath = "VERIFIER_CONFIG_PATH"

	// Database environment variables.
	DatabaseURLEnvVar             = "CL_DATABASE_URL"
	DatabaseMaxOpenConnsEnvVar    = "CL_DATABASE_MAX_OPEN_CONNS"
	DatabaseMaxIdleConnsEnvVar    = "CL_DATABASE_MAX_IDLE_CONNS"
	DatabaseConnMaxLifetimeEnvVar = "CL_DATABASE_CONN_MAX_LIFETIME"
	DatabaseConnMaxIdleTimeEnvVar = "CL_DATABASE_CONN_MAX_IDLE_TIME"

	// Database defaults.
	defaultMaxOpenConns    = 2
	defaultMaxIdleConns    = 1
	defaultConnMaxLifetime = 300 // seconds
	defaultConnMaxIdleTime = 60  // seconds
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

	apiKey := os.Getenv("VERIFIER_AGGREGATOR_API_KEY")
	if apiKey == "" {
		lggr.Errorw("VERIFIER_AGGREGATOR_API_KEY environment variable is required")
		os.Exit(1)
	}
	lggr.Infow("Loaded VERIFIER_AGGREGATOR_API_KEY from environment")

	secretKey := os.Getenv("VERIFIER_AGGREGATOR_SECRET_KEY")
	if secretKey == "" {
		lggr.Errorw("VERIFIER_AGGREGATOR_SECRET_KEY environment variable is required")
		os.Exit(1)
	}
	lggr.Infow("Loaded VERIFIER_AGGREGATOR_SECRET_KEY from environment")

	cmd.StartPyroscope(lggr, config.PyroscopeURL, "verifier")
	blockchainHelper, chainClients := cmd.LoadBlockchainInfo(ctx, lggr, blockchainInfos)

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
	defaultExecutorAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.DefaultExecutorOnRampAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Errorw("Failed to create default executor address", "error", err)
			os.Exit(1)
		}
		defaultExecutorAddresses[selector] = addr
	}

	hmacConfig := &hmac.ClientConfig{
		APIKey: apiKey,
		Secret: secretKey,
	}

	aggregatorWriter, err := storageaccess.NewAggregatorWriter(config.AggregatorAddress, lggr, hmacConfig)
	if err != nil {
		lggr.Errorw("Failed to create aggregator writer", "error", err)
		os.Exit(1)
	}

	// Create chain status manager (PostgreSQL storage).
	chainStatusManager, chainStatusDB, err := createChainStatusManager(lggr)
	if err != nil {
		lggr.Errorw("Failed to create chain status manager", "error", err)
		os.Exit(1)
	}
	defer func() {
		if chainStatusDB != nil {
			_ = chainStatusDB.Close()
		}
	}()

	sourceReaders := cmd.LoadBlockchainReadersForCommit(lggr, blockchainHelper, chainClients, *config)

	// Create coordinator configuration
	sourceConfigs := make(map[protocol.ChainSelector]verifier.SourceConfig)
	rmnRemoteAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.RMNRemoteAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Errorw("Failed to create RMN Remote address", "error", err, "selector", selector)
			os.Exit(1)
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
		}

		lggr.Infow("Configured source chain", "chainSelector", selector)
	}

	coordinatorConfig := verifier.CoordinatorConfig{
		VerifierID:          config.VerifierID,
		SourceConfigs:       sourceConfigs,
		StorageBatchSize:    50,
		StorageBatchTimeout: 100 * time.Millisecond,
		CursePollInterval:   2 * time.Second, // Poll RMN Remotes for curse status every 2s
	}

	pk := os.Getenv(PkEnvVar)
	if pk == "" {
		lggr.Errorf("Environment variable %s is not set", PkEnvVar)
		os.Exit(1)
	}
	privateKey, err := commit.ReadPrivateKeyFromString(pk)
	if err != nil {
		lggr.Errorw("Failed to read private key from environment variable", "error", err)
		os.Exit(1)
	}
	signer, publicKey, err := commit.NewECDSAMessageSigner(privateKey)
	if err != nil {
		lggr.Errorw("Failed to create message signer", "error", err)
		os.Exit(1)
	}
	lggr.Infow("Using signer address", "address", publicKey)

	verifierMonitoring := cmd.SetupOTEL(lggr, config.Monitoring)

	// Create commit verifier
	commitVerifier, err := commit.NewCommitVerifier(coordinatorConfig, publicKey, signer, lggr, verifierMonitoring)
	if err != nil {
		lggr.Errorw("Failed to create commit verifier", "error", err)
		os.Exit(1)
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

	messageTracker := monitoring.NewMessageLatencyTracker(
		lggr,
		config.VerifierID,
		verifierMonitoring,
	)

	// Create verification coordinator
	coordinator, err := verifier.NewCoordinator(
		lggr,
		commitVerifier,
		sourceReaders,
		observedStorageWriter,
		coordinatorConfig,
		messageTracker,
		verifierMonitoring,
		chainStatusManager,
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator", "error", err)
		os.Exit(1)
	}

	// Start the verification coordinator
	lggr.Infow("Starting Verification Coordinator",
		"verifierID", coordinatorConfig.VerifierID,
		"verifierAddress", verifierAddresses,
	)

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Failed to start verification coordinator", "error", err)
		os.Exit(1)
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

	lggr.Infow("Committee service stopped gracefully")
}

func loadConfiguration(filepath string) (*commit.Config, map[string]*protocol.BlockchainInfo, error) {
	var config commit.ConfigWithBlockchainInfos
	if _, err := toml.DecodeFile(filepath, &config); err != nil {
		return nil, nil, err
	}
	return &config.Config, config.BlockchainInfos, nil
}

func createChainStatusManager(lggr logger.Logger) (protocol.ChainStatusManager, *sqlx.DB, error) {
	dbURL := os.Getenv(DatabaseURLEnvVar)
	if dbURL == "" {
		return nil, nil, fmt.Errorf("%s environment variable is required", DatabaseURLEnvVar)
	}

	maxOpenConns := getEnvInt(DatabaseMaxOpenConnsEnvVar, defaultMaxOpenConns)
	maxIdleConns := getEnvInt(DatabaseMaxIdleConnsEnvVar, defaultMaxIdleConns)
	connMaxLifetime := getEnvInt(DatabaseConnMaxLifetimeEnvVar, defaultConnMaxLifetime)
	connMaxIdleTime := getEnvInt(DatabaseConnMaxIdleTimeEnvVar, defaultConnMaxIdleTime)

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open postgres database: %w", err)
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(time.Duration(connMaxLifetime) * time.Second)
	db.SetConnMaxIdleTime(time.Duration(connMaxIdleTime) * time.Second)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("failed to ping postgres database: %w", err)
	}

	sqlxDB := sqlx.NewDb(db, "postgres")

	if err := chainstatus.RunPostgresMigrations(sqlxDB); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("failed to run postgres migrations: %w", err)
	}

	lggr.Infow("Using PostgreSQL chain status storage",
		"maxOpenConns", maxOpenConns,
		"maxIdleConns", maxIdleConns,
		"connMaxLifetime", connMaxLifetime,
		"connMaxIdleTime", connMaxIdleTime,
	)

	return chainstatus.NewPostgresChainStatusManager(sqlxDB, lggr), sqlxDB, nil
}

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
