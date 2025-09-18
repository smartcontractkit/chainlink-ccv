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
	Address   []byte
}

// ToIdentifier converts the CommitVerificationRecordIdentifier to a string identifier.
func (c CommitVerificationRecordIdentifier) ToIdentifier() string {
	return fmt.Sprintf("%x:%x", c.MessageID, hex.EncodeToString(c.Address))
}

// CommitVerificationRecord represents a record of a commit verification.
type CommitVerificationRecord struct {
	IdentifierSigner *IdentifierSigner
	aggregator.MessageWithCCVNodeData
	CommitteeID string
}

// GetID retrieves the unique identifier for the commit verification record.
func (c *CommitVerificationRecord) GetID() (*CommitVerificationRecordIdentifier, error) {
	if len(c.IdentifierSigner.Address) == 0 {
		return nil, fmt.Errorf("address is nil or empty")
	}
	if c.GetMessageId() == nil || len(c.GetMessageId()) == 0 {
		return nil, fmt.Errorf("message ID is nil or empty")
	}

	return &CommitVerificationRecordIdentifier{
		MessageID: c.GetMessageId(),
		Address:   c.IdentifierSigner.Address,
	}, nil
}
