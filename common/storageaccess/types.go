package storageaccess

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type IndexerAPI interface {
	// ReadVerifierResults reads all data that matches the provided query parameters. Returns a map of messageID to an array of all known VerifierResults for that messageID. Does not provide a guarantee that the returned data is enough to be executed.
	ReadVerifierResults(ctx context.Context, queryData VerifierResultsRequest) (map[string][]types.CCVData, error)
}

type VerifierResultsRequest struct {
	Start                int64                 `form:"start"`
	End                  int64                 `form:"end"`
	SourceChainSelectors []types.ChainSelector // Excluded from form due to gin parsing
	DestChainSelectors   []types.ChainSelector // Excluded from form due to gin parsing
	Limit                uint64                `form:"limit"`
	Offset               uint64                `form:"offset"`
}
