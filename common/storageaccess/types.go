package storageaccess

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type IndexerAPI interface {
	ReadCCVData(ctx context.Context, startUnix, endUnix int64, sourceChainSelectors, destChainSelectors []types.ChainSelector, limit, offset uint64) (map[string][]types.CCVData, error)
}
