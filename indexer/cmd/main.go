package main

import (
	"context"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/discovery"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/scanner"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
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

	ctx := context.Background()

	// Use SugaredLogger for better API
	lggr = logger.Sugared(lggr)

	// Initialize the indexer storage & create a reader discovery, which will discover the off-chain storage readers
	// Storage Discovery allows the indexer to add new off-chain storage readers without needing a restart
	// Currently, this uses the configuration discovery method, which reads the off-chain storage readers from the configuration passed to it.
	aggregatorReader, _ := storageaccess.NewAggregatorReader("aggregator:50051", lggr, 0)
	readerDiscovery := discovery.NewStaticDiscovery([]types.OffchainStorageReader{aggregatorReader})

	// Initialize the indexer storage
	indexerStorage := storage.NewInMemoryStorage(lggr)

	// Create a scanner, which will poll the off-chain storage(s) for CCV data
	scanner := scanner.NewScanner(
		scanner.WithReaderDiscovery(readerDiscovery),
		scanner.WithLogger(lggr),
		scanner.WithConfig(scanner.Config{
			ScanInterval: 1 * time.Second,
		}),
		scanner.WithStorageWriter(indexerStorage),
	)

	// Start the Scanner processing
	scanner.Start(ctx)

	v1 := api.NewV1API(lggr, indexerStorage)
	if err := api.Serve(v1, 8100); err != nil {
		lggr.Errorw("Failed to serve API", "error", err)
		os.Exit(1)
	}
}
