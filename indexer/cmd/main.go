package main

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/discovery"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/scanner"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
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
	aggregatorReader, _ := storageaccess.NewAggregatorReader("aggregator:50051", lggr, 0)
	readerDiscovery := discovery.NewConfigurationDiscovery([]types.OffchainStorageReader{aggregatorReader})

	// Initialize the indexer storage
	indexerStorage := storage.NewInMemoryStorage(lggr)

	// Create a scanner, which will poll the off-chain storage(s) for CCV data
	scanner := scanner.NewScanner(
		scanner.WithReaderDiscovery(readerDiscovery),
		scanner.WithLogger(lggr),
		scanner.WithConfig(scanner.ScannerConfig{
			ScanInterval: 1 * time.Second,
		}),
		scanner.WithIndexerStorage(indexerStorage),
	)

	// Start the Scanner processing
	scanner.Start(ctx)

	// go func() {
	// 	ticker := time.NewTicker(1 * time.Millisecond)
	// 	defer ticker.Stop()
	// 	for {
	// 		select {
	// 		case <-ctx.Done():
	// 			return
	// 		case <-ticker.C:
	// 			messageId := make([]byte, 32)
	// 			rand.Read(messageId)
	// 			inMemoryOffchainStorage.WriteCCVData(ctx, []types.CCVData{
	// 				{
	// 					SourceVerifierAddress: []byte{},
	// 					DestVerifierAddress:   []byte{},
	// 					CCVData:               []byte{},
	// 					BlobData:              []byte{},
	// 					ReceiptBlobs:          []types.ReceiptWithBlob{},
	// 					Message:               types.Message{},
	// 					SequenceNumber:        1,
	// 					SourceChainSelector:   1,
	// 					DestChainSelector:     2,
	// 					Timestamp:             time.Now().Unix(),
	// 					MessageID:             types.Bytes32(messageId),
	// 				},
	// 			})
	// 		}
	// 	}
	// }()

	v1 := api.NewV1API(lggr, indexerStorage)
	api.Serve(v1, 8100)
}
