package storageaccess

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type IndexerAPI interface {
	// ReadVerifierResults reads all data that matches the provided query parameters. Returns a map of messageID to an array of all known VerifierResults for that messageID. Does not provide a guarantee that the returned data is enough to be executed.
	ReadVerifierResults(ctx context.Context, startUnix, endUnix int64, sourceChainSelectors, destChainSelectors []types.ChainSelector, limit, offset uint64) (map[string][]types.CCVData, error)
}
