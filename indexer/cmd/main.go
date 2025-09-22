package main

import (
	"context"
	"time"

	"github.com/grafana/pyroscope-go"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/discovery"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/scanner"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func main() {
	// Setup logging
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	})
	if err != nil {
		panic(err)
	}

	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "indexer",
		ServerAddress:   "http://pyroscope:4040",
		Logger:          pyroscope.StandardLogger,
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileBlockDuration,
			pyroscope.ProfileMutexDuration,
		},
	}); err != nil {
		lggr.Errorw("Failed to start pyroscope", "error", err)
	}
	ctx := context.Background()

	// Use SugaredLogger for better API
	lggr = logger.Sugared(lggr)

	// Setup OTEL Monitoring (via beholder)
	indexerMonitoring, err := monitoring.InitMonitoring(beholder.Config{
		InsecureConnection:       true,
		OtelExporterHTTPEndpoint: "otel-collector:4318", // All of this needs to be in config, only works in devenv atm
		LogStreamingEnabled:      false,
		MetricReaderInterval:     10 * time.Second,
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
