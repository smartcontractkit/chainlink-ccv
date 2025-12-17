package protocol

import (
	"time"
)

// TODO: Use github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1.MessagesInput
type MessagesV1Request struct {
	SourceChainSelectors []ChainSelector // Excluded from form due to gin parsing
	DestChainSelectors   []ChainSelector // Excluded from form due to gin parsing
	Start                int64           `form:"start"`
	End                  int64           `form:"end"`
	Limit                uint64          `form:"limit"`
	Offset               uint64          `form:"offset"`
}

// TODO: Use github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1.MessagesResponse
type MessagesV1Response struct {
	Messages map[string]MessageWithMetadata `json:"messages"`
	Error    string                         `json:"error,omitempty"`
	Success  bool                           `json:"success"`
}

type MessageWithMetadata struct {
	Message  Message         `json:"message"`
	Metadata MessageMetadata `json:"metadata"`
}

type MessageMetadata struct {
	IngestionTimestamp time.Time `json:"ingestionTimestamp"`
}

// TODO: Use github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1.MessageIDResponse
type MessageIDV1Response struct {
	Error     string                       `json:"error,omitempty"`
	Success   bool                         `json:"success"`
	MessageID Bytes32                      `json:"messageID"`
	Results   []VerifierResultWithMetadata `json:"results"`
}
type VerifierResultWithMetadata struct {
	VerifierResult VerifierResult   `json:"verifierResult"`
	Metadata       VerifierMetadata `json:"metadata"`
}
type VerifierMetadata struct {
	VerifierName         string    `json:"verifierName"`
	AttestationTimestamp time.Time `json:"attestationTimestamp"`
	IngestionTimestamp   time.Time `json:"ingestionTimestamp"`
}
