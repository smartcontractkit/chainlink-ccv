package model

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pb/aggregator"
)

type MessageID = uint32

type CommitVerificationRecordIdentifier struct {
	MessageID     MessageID
	ParticipantID string
	CommitteeID   string
}

func (c CommitVerificationRecordIdentifier) ToIdentifier() string {
	return fmt.Sprintf("%x:%s:%s", c.MessageID, c.ParticipantID, c.CommitteeID)
}

type CommitVerificationRecord struct {
	aggregator.CommitVerificationRecord
	ParticipantID string
	CommitteeID   string
}

func (c *CommitVerificationRecord) GetID() *CommitVerificationRecordIdentifier {
	return &CommitVerificationRecordIdentifier{
		MessageID:     c.GetMessageId(),
		ParticipantID: c.ParticipantID,
		CommitteeID:   c.CommitteeID,
	}
}
