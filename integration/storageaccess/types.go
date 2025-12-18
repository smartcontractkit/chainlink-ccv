package storageaccess

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// IndexerAPI
// deprecated use the actual indexer client instead of the interface.
type IndexerAPI interface {
	// TODO: Add the 3rd endpoint?
	// ReadVerifierResults reads all verifier results that matches the provided query parameters. Returns a map of messageID to the verifier results.
	// ReadVerifierResults(ctx context.Context, queryData protocol.MessagesV1Request) (map[string][]protocol.VerifierResult, error)

	// ReadMessages reads all messages that matches the provided query parameters. Returns a map of messageID to the contents of the message.
	ReadMessages(ctx context.Context, queryData protocol.MessagesV1Request) (map[string]protocol.MessageWithMetadata, error)
	// GetVerifierResults returns all verifierResults for a given messageID
	GetVerifierResults(ctx context.Context, messageID protocol.Bytes32) ([]protocol.VerifierResult, error)
}

type VerifierResultsRequest struct {
	SourceChainSelectors []protocol.ChainSelector // Excluded from form due to gin parsing
	DestChainSelectors   []protocol.ChainSelector // Excluded from form due to gin parsing
	Start                int64                    `form:"start"`
	End                  int64                    `form:"end"`
	Limit                uint64                   `form:"limit"`
	Offset               uint64                   `form:"offset"`
}

type VerifierResultsResponse struct {
	CCVData map[string][]protocol.VerifierResult `json:"ccvData"`
	Error   string                               `json:"error,omitempty"`
	Success bool                                 `json:"success"`
}
