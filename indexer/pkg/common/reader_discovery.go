package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// ReaderDiscovery defines the interface for discovering the off-chain storage(s) where CCVData is stored.
type ReaderDiscovery interface {
	// DiscoverReaders returns a channel that emits off-chain storage readers once they are discovered.
	DiscoverReaders(ctx context.Context) chan types.OffchainStorageReader
	// Stop the reader discovery
	Stop() error
}
