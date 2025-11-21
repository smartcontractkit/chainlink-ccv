package common

import (
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type VerifierResultWithMetadata struct {
	VerifierResult protocol.CCVData
	Metadata       VerifierResultMetadata
}

type VerifierResultMetadata struct {
	VerifierName         string
	AttestationTimestamp time.Time
	IngestionTimestamp   time.Time
}

type MessageWithMetadata struct {
	Message  protocol.CCVData
	Metadata MessageMetadata
}

type MessageMetadata struct {
	Status             MessageStatus
	IngestionTimestamp time.Time
}
