package model

import (
	"encoding/hex"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

// MessageID is a type alias for bytes representing a message identifier.
type MessageID = []byte

// CommitVerificationRecordIdentifier uniquely identifies a commit verification record.
type CommitVerificationRecordIdentifier struct {
	MessageID MessageID
	PublicKey []byte
}

// ToIdentifier converts the CommitVerificationRecordIdentifier to a string identifier.
func (c CommitVerificationRecordIdentifier) ToIdentifier() string {
	return fmt.Sprintf("%x:%x", c.MessageID, hex.EncodeToString(c.PublicKey))
}

// CommitVerificationRecord represents a record of a commit verification.
type CommitVerificationRecord struct {
	PublicKey []byte
	aggregator.MessageWithCCVNodeData
}

// GetID retrieves the unique identifier for the commit verification record.
func (c *CommitVerificationRecord) GetID() *CommitVerificationRecordIdentifier {
	return &CommitVerificationRecordIdentifier{
		MessageID: c.GetMessageId(),
		PublicKey: c.PublicKey,
	}
}
