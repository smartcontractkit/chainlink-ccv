package main

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api"
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
	indexerConfig, err := config.LoadConfig("config.toml")
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
		InsecureConnection:       indexerConfig.Monitoring.Beholder.InsecureConnection,
		OtelExporterHTTPEndpoint: indexerConfig.Monitoring.Beholder.OtelExporterHTTPEndpoint,
		LogStreamingEnabled:      indexerConfig.Monitoring.Beholder.LogStreamingEnabled,
		MetricReaderInterval:     time.Second * time.Duration(indexerConfig.Monitoring.Beholder.MetricReaderInterval),
	})
	if err != nil {
		lggr.Fatalf("Failed to initialize indexer monitoring: %v", err)
	}

	// Initialize the indexer storage & create a reader discovery, which will discover the off-chain storage readers
	// Storage Discovery allows the indexer to add new off-chain storage readers without needing a restart
	// Currently, this uses the configuration discovery method, which reads the off-chain storage readers from the configuration passed to it.
	aggregatorReader, _ := storageaccess.NewAggregatorReader("aggregator:50051", lggr, 0)
	readerDiscovery := discovery.NewStaticDiscovery([]types.OffchainStorageReader{aggregatorReader})

	// Initialize the indexer storage
	indexerStorage := storage.NewInMemoryStorage(lggr, indexerMonitoring)

	// Create a scanner, which will poll the off-chain storage(s) for CCV data
	scanner := scanner.NewScanner(
		scanner.WithReaderDiscovery(readerDiscovery),
		scanner.WithConfig(scanner.Config{
			ScanInterval:   1 * time.Second,
			MetricInterval: 5 * time.Second,
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
