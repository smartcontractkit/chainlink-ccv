package main

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap/zapcore"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
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
	config, unmatchedVerifierNames, err := config.LoadConfig()
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

	for _, name := range unmatchedVerifierNames {
		lggr.Warnw("Generated config verifier has no matching verifier in main config",
			"name", name)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Setup OTEL Monitoring (via beholder)
	var indexerMonitoring common.IndexerMonitoring
	if config.Monitoring.Enabled {
		indexerMonitoring, err = monitoring.InitMonitoring(beholder.Config{
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
	} else {
		lggr.Infow("Monitoring disabled, using noop implementation")
		indexerMonitoring = monitoring.NewNoopIndexerMonitoring()
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
	pool, err := worker.NewWorkerPool(lggr, config.Pool, discoveryCh, scheduler, verifierRegistry, indexerStorage)
	if err != nil {
		lggr.Fatalf("Failed to initalize worker pool: %v", err)
	}
	pool.Start(ctx)

	v1 := api.NewV1API(lggr, config, indexerStorage, indexerMonitoring)
	listenPort := config.API.ListenPort
	if listenPort == 0 {
		listenPort = 8100
	}
	api.Serve(v1, listenPort)
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

	verifierReader := readers.NewVerifierReader(reader, verifierConfig)

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
		}, cfg.InsecureConnection, config.EffectiveMaxResponseBytes(cfg.MaxResponseBytes))
	case config.ReaderTypeRest:
		return readers.NewRestReader(readers.RestReaderConfig{
			BaseURL:          cfg.BaseURL,
			RequestTimeout:   time.Duration(cfg.RequestTimeout),
			MaxResponseBytes: config.EffectiveMaxResponseBytes(cfg.MaxResponseBytes),
			Logger:           lggr,
		}), nil
	default:
		return nil, errors.New("unknown verifier type")
	}
}

func createDiscovery(ctx context.Context, lggr logger.Logger, cfg *config.Config, storage common.IndexerStorage, monitoring common.IndexerMonitoring, registry *registry.VerifierRegistry) (common.MessageDiscovery, error) {
	configs := cfg.DiscoveryConfigs()
	sources := make([]common.MessageDiscovery, 0, len(configs))
	ntpProviders := make(map[string]*backofftimeprovider.BackoffNTPProvider)

	cleanupOnError := func() {
		for _, src := range sources {
			_ = src.Close()
		}
	}

	// For multi-source setups, share a single PrimaryWriteNotifier across all instances so
	// that the primary (priority 0) can signal secondary sources when its write attempt
	// finishes, allowing them to skip the remainder of their delay.
	var writeNotifier *discovery.PrimaryWriteNotifier
	if len(configs) > 1 {
		writeNotifier = discovery.NewPrimaryWriteNotifier()
	}

	for i, discCfg := range configs {
		persistedSinceValue, err := storage.GetDiscoverySequenceNumber(ctx, discCfg.Address)
		if err != nil {
			lggr.Warnw("Discovery location previously not persisted, using value set in config", "address", discCfg.Address)
			if err := storage.CreateDiscoveryState(ctx, discCfg.Address, int(discCfg.Since)); err != nil {
				lggr.Warnw("Unable to persist discovery sequence number", "address", discCfg.Address)
			}
			persistedSinceValue = int(discCfg.Since)
		}

		aggregator, err := readers.NewAggregatorReader(discCfg.Address, lggr, int64(persistedSinceValue), hmac.ClientConfig{
			APIKey: discCfg.APIKey,
			Secret: discCfg.Secret,
		}, discCfg.InsecureConnection, config.EffectiveMaxResponseBytes(discCfg.MaxResponseBytes))
		if err != nil {
			cleanupOnError()
			return nil, err
		}

		ntpKey := fmt.Sprintf("%s|%d", discCfg.NtpServer, discCfg.Timeout)
		timeProvider, ok := ntpProviders[ntpKey]
		if !ok {
			timeProvider = backofftimeprovider.NewBackoffNTPProvider(lggr, time.Duration(discCfg.Timeout)*time.Second, discCfg.NtpServer)
			ntpProviders[ntpKey] = timeProvider
		}

		aggDiscovery, err := discovery.NewAggregatorMessageDiscovery(
			discovery.WithAggregator(aggregator),
			discovery.WithStorage(storage),
			discovery.WithRegistry(registry),
			discovery.WithTimeProvider(timeProvider),
			discovery.WithMonitoring(monitoring),
			discovery.WithLogger(lggr),
			discovery.WithConfig(discCfg),
			discovery.WithDiscoveryPriority(i),
			discovery.WithPrimaryWriteNotifier(writeNotifier), // nil for single-source; no-op
		)
		if err != nil {
			cleanupOnError()
			return nil, err
		}
		sources = append(sources, aggDiscovery)
	}

	if len(sources) == 1 {
		return sources[0], nil
	}
	opts := []discovery.MultiSourceOption{}
	if cfg.MergeBufferSize > 0 {
		opts = append(opts, discovery.WithMergeBufferSize(cfg.MergeBufferSize))
	}
	multiDiscovery, err := discovery.NewMultiSourceMessageDiscovery(lggr, sources, opts...)
	if err != nil {
		cleanupOnError()
		return nil, err
	}
	return multiDiscovery, nil
}

// createStorage creates the storage backend connection based on the configuration.
func createStorage(ctx context.Context, lggr logger.Logger, cfg *config.Config, indexerMonitoring common.IndexerMonitoring) common.IndexerStorage {
	return createPostgresStorage(ctx, lggr, cfg.Storage.Single.Postgres, indexerMonitoring)
}

// createPostgresStorage creates a PostgreSQL storage backend.
func createPostgresStorage(ctx context.Context, lggr logger.Logger, cfg *config.PostgresConfig, indexerMonitoring common.IndexerMonitoring) common.IndexerStorage {
	// Run migrations first
	migrationsDB, err := sqlx.Open("postgres", cfg.URI)
	if err != nil {
		lggr.Fatalf("Failed to open database for migrations: %v", err)
	}
	if err := ccvcommon.EnsureDBConnection(lggr, migrationsDB.DB); err != nil {
		lggr.Fatalf("Could not connect to database: %v", err)
	}
	if err := storage.RunMigrations(migrationsDB); err != nil {
		lggr.Fatalf("Failed to run database migrations: %v", err)
	}
	if err := migrationsDB.Close(); err != nil {
		lggr.Warnf("Error closing migration database connection: %v", err)
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
