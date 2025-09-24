package main

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/discovery"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/scanner"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func main() {
	// Load in the config from './config.toml'
	config, err := config.LoadConfig()
	if err != nil {
		panic(err)
	}

	// Setup logging
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	})
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	// Use SugaredLogger for better API
	lggr = logger.Sugared(lggr)

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
	indexerStorage := createStorage(lggr, config, indexerMonitoring)

	// Create a scanner, which will poll the off-chain storage(s) for CCV data
	scanner := scanner.NewScanner(
		scanner.WithReaderDiscovery(readerDiscovery),
		scanner.WithConfig(scanner.Config{
			ScanInterval:   time.Duration(config.Scanner.ScanInterval) * time.Second,
			MetricInterval: time.Duration(config.Monitoring.Beholder.MetricReaderInterval) * time.Second,
		}),
		scanner.WithStorageWriter(indexerStorage),
		scanner.WithMonitoring(indexerMonitoring),
		scanner.WithLogger(lggr),
	)

	// Start the Scanner processing
	scanner.Start(ctx)

	v1 := api.NewV1API(lggr, indexerStorage, indexerMonitoring)
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
func createStaticReaders(lggr logger.Logger, cfg *config.Config) []types.OffchainStorageReader {
	readers := []types.OffchainStorageReader{}

	// Iterate over the readers and create the appropriate reader
	for _, reader := range cfg.Discovery.Static.Readers {
		switch reader.Type {
		case config.ReaderTypeAggregator:
			aggReader, err := storageaccess.NewAggregatorReader(reader.Aggregator.Address, lggr, reader.Aggregator.Since)
			if err != nil {
				lggr.Fatalf("Failed to create aggregator reader: %v", err)
			}
			readers = append(readers, aggReader)
		default:
			lggr.Fatalf("Unsupported reader type: %s", reader.Type)
		}
	}

	// Return the readers
	return readers
}

// createStorage creates the storage backend connection based on the configuration.
func createStorage(lggr logger.Logger, cfg *config.Config, indexerMonitoring common.IndexerMonitoring) common.IndexerStorage {
	// Determine the appropriate storage backend based on the configuration
	switch cfg.Storage.Type {
	case config.StorageTypeMemory:
		// Create a new in-memory storage
		return storage.NewInMemoryStorage(lggr, indexerMonitoring)
	default:
		lggr.Fatalf("Unsupported storage type: %s", cfg.Storage.Type)
	}

	return nil
}
