package storageaccess

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type IndexerAPI interface {
	// ReadVerifierResults reads all data that matches the provided query parameters. Returns a map of messageID to an array of all known VerifierResults for that messageID. Does not provide a guarantee that the returned data is enough to be executed.
	ReadVerifierResults(ctx context.Context, queryData VerifierResultsRequest) (map[string][]protocol.CCVData, error)
	// ReadMessages reads all messages that matches the provided query parameters. Returns a map of messageID to the contents of the message.
	ReadMessages(ctx context.Context, queryData MessagesV1Request) (map[string]protocol.Message, error)
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

type MessagesV1Request struct {
	SourceChainSelectors []protocol.ChainSelector // Excluded from form due to gin parsing
	DestChainSelectors   []protocol.ChainSelector // Excluded from form due to gin parsing
	Start                int64                    `form:"start"`
	End                  int64                    `form:"end"`
	Limit                uint64                   `form:"limit"`
	Offset               uint64                   `form:"offset"`
}

type MessagesV1Response struct {
	Messages map[string]protocol.Message `json:"messages"`
	Error    string                      `json:"error,omitempty"`
	Success  bool                        `json:"success"`
}

type MessageIDV1Response struct {
	Error           string             `json:"error,omitempty"`
	Success         bool               `json:"success"`
	VerifierResults []protocol.CCVData `json:"ccvData"`
}
