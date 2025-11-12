package model

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// MessageID is a type alias for bytes representing a message identifier.
type MessageID = []byte

// AggregationKey is a type alias that represent the key on which the aggregation is performed.
type AggregationKey = string

type OrphanedKey struct {
	MessageID      MessageID
	AggregationKey AggregationKey
	CommitteeID    CommitteeID
}

// CommitVerificationRecordIdentifier uniquely identifies a commit verification record.
type CommitVerificationRecordIdentifier struct {
	MessageID   MessageID
	Address     []byte
	CommitteeID CommitteeID
}

// ToIdentifier converts the CommitVerificationRecordIdentifier to a string identifier.
func (c CommitVerificationRecordIdentifier) ToIdentifier() string {
	return fmt.Sprintf("%x:%x:%s", c.MessageID, hex.EncodeToString(c.Address), c.CommitteeID)
}

// CommitVerificationRecord represents a record of a commit verification.
type CommitVerificationRecord struct {
	MessageID             MessageID
	SourceVerifierAddress []byte
	Message               *protocol.Message
	BlobData              []byte
	CcvData               []byte
	Timestamp             time.Time
	ReceiptBlobs          []*ReceiptBlob
	IdentifierSigner      *IdentifierSigner
	CommitteeID           CommitteeID
	IdempotencyKey        uuid.UUID
}

// GetID retrieves the unique identifier for the commit verification record.
func (c *CommitVerificationRecord) GetID() (*CommitVerificationRecordIdentifier, error) {
	if len(c.IdentifierSigner.Address) == 0 {
		return nil, fmt.Errorf("address is nil or empty")
	}
	if len(c.MessageID) == 0 {
		return nil, fmt.Errorf("message ID is nil or empty")
	}

	return &CommitVerificationRecordIdentifier{
		MessageID:   c.MessageID,
		Address:     c.IdentifierSigner.Address,
		CommitteeID: c.CommitteeID,
	}, nil
}

// SetTimestampFromMillis sets the timestamp from milliseconds since Unix epoch.
func (c *CommitVerificationRecord) SetTimestampFromMillis(timestampMillis int64) {
	c.Timestamp = time.UnixMilli(timestampMillis).UTC()
}

// GetTimestamp returns the domain model's Timestamp field.
func (c *CommitVerificationRecord) GetTimestamp() time.Time {
	return c.Timestamp
}
