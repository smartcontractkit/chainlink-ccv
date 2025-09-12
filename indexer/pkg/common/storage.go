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
	// QueryCCVData retrieves all CCVData that matches the filter set
	QueryCCVData(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []types.ChainSelector, limit, offset uint64) (map[string][]types.CCVData, error)
	// InsertCCVData appends a new CCVData to the storage for the given messageID
	InsertCCVData(ctx context.Context, ccvData types.CCVData) error
}
