package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/pressly/goose/v3"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/discovery"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
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

	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}

	lggr = logger.Named(lggr, "indexer")
	// Use SugaredLogger for better API
	lggr = logger.Sugared(lggr)

	ctx := context.Background()

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

	// Initialize the indexer storage & create a reader discovery, which will discover the off-chain storage readers
	// Storage Discovery allows the indexer to add new off-chain storage readers without needing a restart
	// Currently, this uses the static discovery method, which reads the off-chain storage readers from the configuration passed to it.
	readerDiscovery := createReaderDiscovery(lggr, config)

	// Initialize the indexer storage
	indexerStorage := createStorage(ctx, lggr, config, indexerMonitoring)

	v1 := api.NewV1API(lggr, config, indexerStorage, indexerMonitoring)
	api.Serve(v1, 8100)
}

// createReaderDiscovery creates the appropriate reader discovery based on the configuration.
func createReaderDiscovery(lggr logger.Logger, cfg *config.Config) common.ReaderDiscovery {
	// Determine the appropriate reader discovery based on the configuration
	switch cfg.Discovery.Type {
	case config.DiscoveryTypeStatic:
		return discovery.NewStaticDiscovery(createStaticReaders(lggr, cfg))
	default:
		lggr.Fatalf("Unsupported discovery type: %s", cfg.Discovery.Type)
	}

	return nil
}

// createStaticReaders creates the static readers based on the configuration.
func createStaticReaders(lggr logger.Logger, cfg *config.Config) []protocol.OffchainStorageReader {
	readerSlice := []protocol.OffchainStorageReader{}

	// Iterate over the readers and create the appropriate reader
	for _, reader := range cfg.Discovery.Static.Readers {
		switch reader.Type {
		case config.ReaderTypeAggregator:
			aggReader, err := readers.NewAggregatorReader(reader.Aggregator.Address, lggr, reader.Aggregator.Since)
			if err != nil {
				lggr.Fatalf("Failed to create aggregator reader: %v", err)
			}
			readerSlice = append(readerSlice, aggReader)
		case config.ReaderTypeRest:
			restReader := readers.NewRestReader(readers.RestReaderConfig{
				BaseURL:        reader.Rest.BaseURL,
				Since:          reader.Rest.Since,
				RequestTimeout: time.Duration(reader.Rest.RequestTimeout) * time.Second,
				Logger:         lggr,
			})
			readerSlice = append(readerSlice, restReader)
		default:
			lggr.Fatalf("Unsupported reader type: %s", reader.Type)
		}
	}

	lggr.Infof("Created %d readers", len(readerSlice))
	// Return the readers
	return readerSlice
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
	storagesWithConditions := make([]storage.WithCondition, 0, len(cfg.Storages))

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

		// Create the read condition
		readCondition := createReadCondition(storageCfg.ReadCondition)

		storagesWithConditions = append(storagesWithConditions, storage.WithCondition{
			Storage:   storageBackend,
			Condition: readCondition,
		})
	}

	// Create the storage sink
	sink, err := storage.NewSink(lggr, storagesWithConditions...)
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

// createReadCondition creates a read condition from configuration.
func createReadCondition(cfg config.ReadConditionConfig) storage.ReadCondition {
	switch cfg.Type {
	case config.ReadConditionAlways:
		return storage.AlwaysRead()
	case config.ReadConditionNever:
		return storage.NeverRead()
	case config.ReadConditionTimeRange:
		return storage.TimeRangeRead(cfg.StartUnix, cfg.EndUnix)
	case config.ReadConditionRecent:
		duration := time.Duration(*cfg.LookbackWindowSeconds) * time.Second
		return storage.RecentRead(duration)
	default:
		// Default to always read if unknown type
		return storage.AlwaysRead()
	}
}

// runMigrations runs all pending database migrations using goose.
func runMigrations(lggr logger.Logger, dbURI, migrationsDir string) error {
	// Open a connection to the database for migrations
	db, err := sql.Open("postgres", dbURI)
	if err != nil {
		return err
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
