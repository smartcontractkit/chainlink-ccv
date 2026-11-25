package common

import (
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type VerifierResultWithMetadata struct {
	VerifierResult protocol.VerifierResult `json:"verifierResult"`
	Metadata       VerifierResultMetadata  `json:"metadata"`
}

type VerifierResultMetadata struct {
	VerifierName         string    `json:"verifierName"`
	AttestationTimestamp time.Time `json:"attestationTimestamp"`
	IngestionTimestamp   time.Time `json:"ingestionTimestamp"`
	TraceParent          string    `json:"-"`
}

type MessageWithMetadata struct {
	Message             protocol.Message          `json:"message"`
	Metadata            MessageMetadata           `json:"metadata"`
	MessageCCVAddresses []protocol.UnknownAddress `json:"messageCCVAddresses,omitempty"`
}

type MessageMetadata struct {
	Status             MessageStatus `json:"status"`
	IngestionTimestamp time.Time     `json:"ingestionTimestamp"`
	LastErr            string        `json:"-"` // we want to exclude potentionally sensitive errors
	// TraceParent is the w3c traceparent of the discovery span, so the worker span is its child.
	TraceParent string `json:"-"`
}

const SequenceNumberNotSupported = -1

type DiscoveryBatch struct {
	Messages          []MessageWithMetadata
	Verifications     []VerifierResultWithMetadata
	DiscoveryLocation string
	SequenceNumber    int
}
