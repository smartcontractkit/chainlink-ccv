package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// IndexerStorage defines the interface for all storage operations for the indexer.
// Implementations should be thread-safe.
type IndexerStorage interface {
	IndexerStorageReader
	IndexerStorageWriter
}

type IndexerStorageReader interface {
	// GetCCVData using the messageID for a o(1) lookup
	GetCCVData(ctx context.Context, messageID protocol.Bytes32) ([]protocol.CCVData, error)
	// QueryCCVData retrieves all CCVData that matches the filter set
	QueryCCVData(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []protocol.ChainSelector, limit, offset uint64) (map[string][]protocol.CCVData, error)
}

type IndexerStorageWriter interface {
	// InsertCCVData appends a new CCVData to the storage for the given messageID
	InsertCCVData(ctx context.Context, ccvData protocol.CCVData) error
	BatchInsertCCVData(ctx context.Context, ccvDataList []protocol.CCVData) error
}
