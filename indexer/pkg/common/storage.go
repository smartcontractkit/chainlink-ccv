package common

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// IndexerStorage defines the interface for all storage operations for the indexer.
// Implementations should be thread-safe.
type IndexerStorage interface {
	types.IndexerStorageReader
	types.IndexerStorageWriter
}
