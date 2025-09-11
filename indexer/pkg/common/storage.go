package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// IndexerStorage defines the interface for all storage operations for the indexer.
// Implementations should be thread-safe.
type IndexerStorage interface {
	// Retrieval of CCV data using the messageID for a o(1) lookup
	GetCCVData(ctx context.Context, messageID types.Bytes32) ([]types.CCVData, error)
	// QueryCCVDataByTimestamp retrieves all CCVData within a given timestamp range
	QueryCCVDataByTimestamp(ctx context.Context, start, end int64) (map[string][]types.CCVData, error)
	// InsertCCVData appends a new CCVData to the storage for the given messageID
	InsertCCVData(ctx context.Context, ccvData types.CCVData) error
}
