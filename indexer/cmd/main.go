package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/discovery"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/scanner"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"go.uber.org/zap"
)

func main() {
	// Setup logging
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
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
	inMemoryOffchainStorage := storageaccess.NewInMemoryOffchainStorage(lggr)
	readerDiscovery := discovery.NewConfigurationDiscovery([]types.OffchainStorageReader{storageaccess.CreateReaderOnly(inMemoryOffchainStorage)})

	// Create a scanner, which will poll the off-chain storage(s) for CCV data
	scanner := scanner.NewScanner(
		scanner.WithReaderDiscovery(readerDiscovery),
		scanner.WithLogger(lggr),
		scanner.WithConfig(scanner.ScannerConfig{
			ScanInterval: 1 * time.Second,
		}),
	)

	// Start the Scanner processing
	scanner.Start(ctx)

	// TODO: Add the Read API here, which will query the indexer storage for CCV data
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Indexer is running!\n")
	})

	lggr.Infow("Indexer is running on port :8100")
	if err := http.ListenAndServe(":8100", nil); err != nil {
		lggr.Errorw("Failed to start indexer", "error", err)
		os.Exit(1)
	}
}
