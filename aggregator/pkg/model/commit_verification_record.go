package model

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pb/aggregator"
)

// MessageID is a type alias for bytes representing a message identifier.
type MessageID = uint32

// CommitVerificationRecordIdentifier uniquely identifies a commit verification record.
type CommitVerificationRecordIdentifier struct {
	MessageID     MessageID
	ParticipantID string
	CommitteeID   string
}

// ToIdentifier converts the CommitVerificationRecordIdentifier to a string identifier.
func (c CommitVerificationRecordIdentifier) ToIdentifier() string {
	return fmt.Sprintf("%x:%s:%s", c.MessageID, c.ParticipantID, c.CommitteeID)
}

// CommitVerificationRecord represents a record of a commit verification.
type CommitVerificationRecord struct {
	aggregator.CommitVerificationRecord
	ParticipantID string
	CommitteeID   string
}

// GetID retrieves the unique identifier for the commit verification record.
func (c *CommitVerificationRecord) GetID() *CommitVerificationRecordIdentifier {
	return &CommitVerificationRecordIdentifier{
		MessageID:     c.GetMessageId(),
		ParticipantID: c.ParticipantID,
		CommitteeID:   c.CommitteeID,
	}
}
