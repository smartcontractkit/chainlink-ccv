package protocol

import "time"

type MessagesV1Request struct {
	SourceChainSelectors []ChainSelector // Excluded from form due to gin parsing
	DestChainSelectors   []ChainSelector // Excluded from form due to gin parsing
	Start                int64           `form:"start"`
	End                  int64           `form:"end"`
	Limit                uint64          `form:"limit"`
	Offset               uint64          `form:"offset"`
}

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

type MessageIDV1Response struct {
	Error   string                       `json:"error,omitempty"`
	Success bool                         `json:"success"`
	Results []VerifierResultWithMetadata `json:"results"`
}

type VerifierResultWithMetadata struct {
	VerifierResult CCVData          `json:"verifierResult"`
	Metadata       VerifierMetadata `json:"metadata"`
}

type VerifierMetadata struct {
	VerifierName         string    `json:"verifierName"`
	AttestationTimestamp time.Time `json:"attestationTimestamp"`
	IngestionTimestamp   time.Time `json:"ingestionTimestamp"`
}
