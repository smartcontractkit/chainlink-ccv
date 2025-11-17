package v1

import "github.com/smartcontractkit/chainlink-ccv/protocol"

type MessageIDV1Response struct {
	MessageID     string             `json:"messageID"`
	Verifications []protocol.CCVData `json:"verifications"`
}

type MessagesV1Request struct {
	SourceChainSelectors []protocol.ChainSelector // Excluded from form due to gin parsing
	DestChainSelectors   []protocol.ChainSelector // Excluded from form due to gin parsing
	Start                int64                    `form:"start"`
	End                  int64                    `form:"end"`
	Limit                uint64                   `form:"limit"`
	Offset               uint64                   `form:"offset"`
}

type VerifierResultsV1Request struct {
	SourceChainSelectors []protocol.ChainSelector // Excluded from form due to gin parsing
	DestChainSelectors   []protocol.ChainSelector // Excluded from form due to gin parsing
	Start                int64                    `form:"start"`
	End                  int64                    `form:"end"`
	Limit                uint64                   `form:"limit"`
	Offset               uint64                   `form:"offset"`
}
