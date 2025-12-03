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
	VerifierName              string    `json:"verifierName"`
	AttestationTimestamp      time.Time `json:"attestationTimestamp"`
	IngestionTimestamp        time.Time `json:"ingestionTimestamp"`
	SourceChainBlockTimestamp time.Time `json:"sourceChainBlockTimestamp"`
}

type MessageWithMetadata struct {
	Message  protocol.Message `json:"message"`
	Metadata MessageMetadata  `json:"metadata"`
}

type MessageMetadata struct {
	Status             MessageStatus `json:"status"`
	IngestionTimestamp time.Time     `json:"ingestionTimestamp"`
	LastErr            string        `json:"-"` // we want to exclude potentionally sensitive errors
}
