package model

import (
	"encoding/hex"
	"fmt"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// MessageID is a type alias for bytes representing a message identifier.
type MessageID = []byte

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
	IdentifierSigner *IdentifierSigner
	pb.MessageWithCCVNodeData
	CommitteeID CommitteeID
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
		MessageID:   c.GetMessageId(),
		Address:     c.IdentifierSigner.Address,
		CommitteeID: c.CommitteeID,
	}, nil
}
