package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// ReaderDiscovery defines the interface for discovering the off-chain storage(s) where CCVData is stored.
type ReaderDiscovery interface {
	// Starts the Reader Discovery and returns a channel that emits off-chain storage readers once they are discovered.
	Run(ctx context.Context) chan types.OffchainStorageReader
	// AddReaders adds new off-chain storage readers to the discovery channel
	AddReaders(readers []types.OffchainStorageReader)
	// Stop the reader discovery
	Stop() error
}
