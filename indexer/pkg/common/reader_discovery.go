package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// ReaderDiscovery defines the interface for discovering the off-chain storage(s) where CCVData is stored.
type ReaderDiscovery interface {
	// Run the Reader Discovery service, returns a channel that emits off-chain storage readers once they are discovered.
	Run(ctx context.Context) chan protocol.OffchainStorageReader
	// AddReaders adds new off-chain storage readers to the discovery channel
	AddReaders(readers []protocol.OffchainStorageReader)
	// Stop the reader discovery
	Stop() error
}
