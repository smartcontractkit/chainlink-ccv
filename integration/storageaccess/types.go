package storageaccess

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type IndexerAPI interface {
	// ReadMessages reads all messages that matches the provided query parameters. Returns a map of messageID to the contents of the message.
	ReadMessages(ctx context.Context, queryData protocol.MessagesV1Request) (map[string]protocol.Message, error)
	// GetVerifierResults returns all verifierResults for a given messageID
	GetVerifierResults(ctx context.Context, messageID protocol.Bytes32) ([]protocol.CCVData, error)
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
	CCVData map[string][]protocol.CCVData `json:"ccvData"`
	Error   string                        `json:"error,omitempty"`
	Success bool                          `json:"success"`
}
