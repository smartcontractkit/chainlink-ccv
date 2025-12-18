package model

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// MessageID is a type alias for bytes representing a message identifier.
type MessageID = []byte

// AggregationKey is a type alias that represent the key on which the aggregation is performed.
type AggregationKey = string

// SignableHash represents a 32-byte hash used for signature verification.
type SignableHash = [32]byte

// SignatureValidationResult contains the result of validating a signature.
type SignatureValidationResult struct {
	Signer       *SignerIdentifier
	QuorumConfig *QuorumConfig
	Hash         SignableHash
}

type OrphanedKey struct {
	MessageID      MessageID
	AggregationKey AggregationKey
}

// CommitVerificationRecordIdentifier uniquely identifies a commit verification record.
type CommitVerificationRecordIdentifier struct {
	MessageID MessageID
	Address   []byte
}

// ToIdentifier converts the CommitVerificationRecordIdentifier to a string identifier.
func (c CommitVerificationRecordIdentifier) ToIdentifier() string {
	return fmt.Sprintf("%x:%x", c.MessageID, hex.EncodeToString(c.Address))
}

// CommitVerificationRecord represents a record of a commit verification.
type CommitVerificationRecord struct {
	MessageID              MessageID
	Message                *protocol.Message
	CCVVersion             []byte
	Signature              []byte
	MessageCCVAddresses    []protocol.UnknownAddress
	MessageExecutorAddress protocol.UnknownAddress
	SignerIdentifier       *SignerIdentifier
	createdAt              time.Time // Internal field for tracking creation time from DB
}

// GetID retrieves the unique identifier for the commit verification record.
func (c *CommitVerificationRecord) GetID() (*CommitVerificationRecordIdentifier, error) {
	if len(c.SignerIdentifier.Identifier) == 0 {
		return nil, fmt.Errorf("identifier is nil or empty")
	}
	if len(c.MessageID) == 0 {
		return nil, fmt.Errorf("message ID is nil or empty")
	}

	return &CommitVerificationRecordIdentifier{
		MessageID: c.MessageID,
		Address:   c.SignerIdentifier.Identifier,
	}, nil
}

// SetTimestampFromMillis sets the internal timestamp from milliseconds since Unix epoch.
func (c *CommitVerificationRecord) SetTimestampFromMillis(timestampMillis int64) {
	c.createdAt = time.UnixMilli(timestampMillis).UTC()
}

// GetTimestamp returns the internal creation timestamp.
func (c *CommitVerificationRecord) GetTimestamp() time.Time {
	return c.createdAt
}
