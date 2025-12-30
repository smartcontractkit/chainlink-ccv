package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/pressly/goose/v3"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/discovery"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/worker"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/backofftimeprovider"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil/pg"
)

func main() {
	// Load in the config from './config.toml'
	config, err := config.LoadConfig()
	if err != nil {
		panic(err)
	}

	logLevel, err := zapcore.ParseLevel(config.LogLevel)
	if err != nil {
		panic(err)
	}

	lggr, err := logger.NewWith(logging.DevelopmentConfig(logLevel))
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}

	lggr = logger.Named(lggr, "indexer")
	// Use SugaredLogger for better API
	lggr = logger.Sugared(lggr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Setup OTEL Monitoring (via beholder)
	indexerMonitoring, err := monitoring.InitMonitoring(beholder.Config{
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
		lggr.Fatalf("Failed to initialize indexer monitoring: %v", err)
	}

	// Initialize the indexer storage
	indexerStorage := createStorage(ctx, lggr, config, indexerMonitoring)
	verifierRegistry := createRegistry()
	err = createAllVerifierReaders(ctx, lggr, verifierRegistry, config)
	if err != nil {
		lggr.Fatalf("Failed to initalize verifier readers: %v", err)
	}

	messageDiscovery, err := createDiscovery(ctx, lggr, config, indexerStorage, indexerMonitoring, verifierRegistry)
	if err != nil {
		lggr.Fatalf("Failed to initialize message discovery: %v", err)
	}

	scheduler, err := worker.NewScheduler(lggr, config.Scheduler)
	if err != nil {
		lggr.Fatalf("Failed to initalize scheduler: %v", err)
	}
	scheduler.Start(ctx)

	discoveryCh := messageDiscovery.Start(ctx)
	pool := worker.NewWorkerPool(lggr, config.Pool, discoveryCh, scheduler, verifierRegistry, indexerStorage)
	pool.Start(ctx)

	v1 := api.NewV1API(lggr, config, indexerStorage, indexerMonitoring)
	api.Serve(v1, 8100)
}

func createRegistry() *registry.VerifierRegistry {
	return registry.NewVerifierRegistry()
}

func createAllVerifierReaders(ctx context.Context, lggr logger.Logger, verifierRegistry *registry.VerifierRegistry, config *config.Config) error {
	for _, verifierConfig := range config.Verifiers {
		err := createReadersForVerifier(ctx, lggr, verifierRegistry, &verifierConfig)
		if err != nil {
			return err
		}
	}

	return nil
}

func createReadersForVerifier(ctx context.Context, lggr logger.Logger, verifierRegistry *registry.VerifierRegistry, verifierConfig *config.VerifierConfig) error {
	reader, err := createReader(lggr, verifierConfig)
	if err != nil {
		return err
	}

	verifierReader := readers.NewVerifierReader(ctx, reader, verifierConfig)

	if err := verifierReader.Start(ctx); err != nil {
		return err
	}

	for _, address := range verifierConfig.IssuerAddresses {
		unknownAddress, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			return err
		}

		err = verifierRegistry.AddVerifier(unknownAddress, verifierConfig.Name, verifierReader)
		if err != nil {
			return err
		}
	}

	return nil
}

func createReader(lggr logger.Logger, cfg *config.VerifierConfig) (*readers.ResilientReader, error) {
	switch cfg.Type {
	case config.ReaderTypeAggregator:
		return readers.NewAggregatorReader(cfg.Address, lggr, cfg.Since, hmac.ClientConfig{
			APIKey: cfg.APIKey,
			Secret: cfg.Secret,
		}, cfg.InsecureConnection)
	case config.ReaderTypeRest:
		return readers.NewRestReader(readers.RestReaderConfig{
			BaseURL:        cfg.BaseURL,
			RequestTimeout: time.Duration(cfg.RequestTimeout),
		}), nil
	default:
		return nil, errors.New("unknown verifier type")
	}
}

func createDiscovery(ctx context.Context, lggr logger.Logger, cfg *config.Config, storage common.IndexerStorage, monitoring common.IndexerMonitoring, registry *registry.VerifierRegistry) (common.MessageDiscovery, error) {
	persistedSinceValue, err := storage.GetDiscoverySequenceNumber(ctx, cfg.Discovery.Address)
	if err != nil {
		lggr.Warnw("Discovery Location previously not persisted, using value set in config")
		if err := storage.CreateDiscoveryState(ctx, cfg.Discovery.Address, int(cfg.Discovery.Since)); err != nil {
			lggr.Warnw("Unable to persist discovery sequence number")
		}
		persistedSinceValue = int(cfg.Discovery.Since)
	}

	aggregator, err := readers.NewAggregatorReader(cfg.Discovery.Address, lggr, int64(persistedSinceValue), hmac.ClientConfig{
		APIKey: cfg.Discovery.APIKey,
		Secret: cfg.Discovery.Secret,
	}, cfg.Discovery.InsecureConnection)
	if err != nil {
		return nil, err
	}

	timeProvider := backofftimeprovider.NewBackoffNTPProvider(lggr, time.Duration(cfg.Discovery.Timeout)*time.Second, cfg.Discovery.NtpServer)

	return discovery.NewAggregatorMessageDiscovery(
		discovery.WithAggregator(aggregator),
		discovery.WithStorage(storage),
		discovery.WithRegistry(registry),
		discovery.WithTimeProvider(timeProvider),
		discovery.WithMonitoring(monitoring),
		discovery.WithLogger(lggr),
		discovery.WithConfig(cfg.Discovery))
}

// createStorage creates the storage backend connection based on the configuration.
func createStorage(ctx context.Context, lggr logger.Logger, cfg *config.Config, indexerMonitoring common.IndexerMonitoring) common.IndexerStorage {
	// Determine the appropriate storage strategy based on the configuration
	switch cfg.Storage.Strategy {
	case config.StorageStrategySingle:
		return createSingleStorage(ctx, lggr, cfg.Storage.Single, indexerMonitoring)
	case config.StorageStrategySink:
		return createSinkStorage(ctx, lggr, cfg.Storage.Sink, indexerMonitoring)
	default:
		lggr.Fatalf("Unsupported storage strategy: %s", cfg.Storage.Strategy)
	}

	return nil
}

// createSingleStorage creates a single storage backend based on the configuration.
func createSingleStorage(ctx context.Context, lggr logger.Logger, cfg *config.SingleStorageConfig, indexerMonitoring common.IndexerMonitoring) common.IndexerStorage {
	switch cfg.Type {
	case config.StorageBackendTypeMemory:
		return createInMemoryStorage(lggr, cfg.Memory, indexerMonitoring)
	case config.StorageBackendTypePostgres:
		return createPostgresStorage(ctx, lggr, cfg.Postgres, indexerMonitoring)
	default:
		lggr.Fatalf("Unsupported storage backend type: %s", cfg.Type)
	}

	return nil
}

// createSinkStorage creates a storage sink with multiple backends based on the configuration.
func createSinkStorage(ctx context.Context, lggr logger.Logger, cfg *config.SinkStorageConfig, indexerMonitoring common.IndexerMonitoring) common.IndexerStorage {
	storages := make([]common.IndexerStorage, 0, len(cfg.Storages))

	for i, storageCfg := range cfg.Storages {
		lggr.Infof("Creating storage backend %d of %d (type: %s)", i+1, len(cfg.Storages), storageCfg.Type)

		// Create the storage backend
		var storageBackend common.IndexerStorage
		switch storageCfg.Type {
		case config.StorageBackendTypeMemory:
			storageBackend = createInMemoryStorage(lggr, storageCfg.Memory, indexerMonitoring)
		case config.StorageBackendTypePostgres:
			storageBackend = createPostgresStorage(ctx, lggr, storageCfg.Postgres, indexerMonitoring)
		default:
			lggr.Fatalf("Unsupported storage backend type: %s", storageCfg.Type)
		}

		storages = append(storages, storageBackend)
	}

	// Create the storage sink
	sink, err := storage.NewSink(lggr, storages...)
	if err != nil {
		lggr.Fatalf("Failed to create storage sink: %v", err)
	}

	lggr.Infof("Successfully created storage sink with %d backends", len(cfg.Storages))
	return sink
}

// createInMemoryStorage creates an in-memory storage backend.
func createInMemoryStorage(lggr logger.Logger, cfg *config.InMemoryStorageConfig, indexerMonitoring common.IndexerMonitoring) common.IndexerStorage {
	// If no config provided, use defaults (no eviction)
	if cfg == nil {
		return storage.NewInMemoryStorage(lggr, indexerMonitoring)
	}

	// Create with eviction configuration
	storageConfig := storage.InMemoryStorageConfig{
		TTL:             time.Duration(cfg.TTL) * time.Second,
		MaxSize:         cfg.MaxSize,
		CleanupInterval: time.Duration(cfg.CleanupInterval) * time.Second,
	}

	return storage.NewInMemoryStorageWithConfig(lggr, indexerMonitoring, storageConfig)
}

// createPostgresStorage creates a PostgreSQL storage backend.
func createPostgresStorage(ctx context.Context, lggr logger.Logger, cfg *config.PostgresConfig, indexerMonitoring common.IndexerMonitoring) common.IndexerStorage {
	// Run migrations first
	migrationsDir := "./migrations"
	if err := runMigrations(lggr, cfg.URI, migrationsDir); err != nil {
		lggr.Fatalf("Failed to run database migrations: %v", err)
	}

	// Create postgres database configuration
	dbConfig := pg.DBConfig{
		MaxOpenConns:           cfg.MaxOpenConnections,
		MaxIdleConns:           cfg.MaxIdleConnections,
		IdleInTxSessionTimeout: time.Duration(cfg.IdleInTxSessionTimeout) * time.Second,
		LockTimeout:            time.Duration(cfg.LockTimeout) * time.Second,
	}

	// Create a new postgres storage
	dbStore, err := storage.NewPostgresStorage(ctx, lggr, indexerMonitoring, cfg.URI, pg.DriverPostgres, dbConfig)
	if err != nil {
		lggr.Fatalf("Failed to create postgres storage: %v", err)
	}

	return dbStore
}

// ensureDBConnection ensures that the database is up and running by pinging it.
func ensureDBConnection(lggr logger.Logger, db *sql.DB) error {
	const (
		maxRetries    = 10
		timeout       = 1 * time.Second
		retryInterval = 3 * time.Second
	)
	pingFn := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return db.PingContext(ctx)
	}
	for range maxRetries {
		err := pingFn()
		if err == nil {
			return nil
		}
		lggr.Warnw("failed to connect to database, retrying after sleeping",
			"err", err,
			"retryInterval", retryInterval.String(),
			"maxRetries", maxRetries)
		time.Sleep(retryInterval)
	}
	return fmt.Errorf("failed to connect to database after %d retries", maxRetries)
}

// runMigrations runs all pending database migrations using goose.
func runMigrations(lggr logger.Logger, dbURI, migrationsDir string) error {
	// Open a connection to the database for migrations
	db, err := sql.Open("postgres", dbURI)
	if err != nil {
		return err
	}

	err = ensureDBConnection(lggr, db)
	if err != nil {
		return fmt.Errorf("could not connect to database: %w", err)
	}

	defer func() {
		if cerr := db.Close(); cerr != nil {
			lggr.Warnf("Error closing database: %v", cerr)
		}
	}()

	// Set goose dialect
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	// Run migrations
	if err := goose.Up(db, migrationsDir); err != nil {
		return err
	}

	lggr.Info("Database migrations completed successfully")
	return nil
}
