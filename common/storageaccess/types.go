package storageaccess

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type IndexerAPI interface {
	// Reads all CCVData that matches the provided query parameters. Returns a map of messageID to an array of all known CCVData for that messageID. Does not provide a guarantee that the returned CCVData is enough to be executed.
	ReadCCVData(ctx context.Context, startUnix, endUnix int64, sourceChainSelectors, destChainSelectors []types.ChainSelector, limit, offset uint64) (map[string][]types.CCVData, error)
}
