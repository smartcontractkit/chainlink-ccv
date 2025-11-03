package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// ReaderDiscovery defines the interface for discovering the off-chain storage(s) where CCVData is stored.
type ReaderDiscovery interface {
	// Run the Reader Discovery service, returns a channel that emits off-chain storage readers once they are discovered.
	Run(ctx context.Context) chan protocol.OffchainStorageReader
	// AddReaders adds new off-chain storage readers to the discovery channel.
	AddReaders(readers []protocol.OffchainStorageReader)
	// Stop the reader discovery.
	Stop() error
}

// MessageDiscovery defines the interface for discovering messages from a trusted discovery source.
type MessageDiscovery interface {
	// Start MessageDiscovery and listen to new CCIP Messages.
	Start(ctx context.Context) chan protocol.Message
	// Close gracefully stops MessageDiscovery.
	Close() error
	// Replay messages since a given sequence number until an inclusive end value.
	Replay(ctx context.Context, start, end uint64) error
}
