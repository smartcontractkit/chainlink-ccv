package interfaces

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

type CommitVerificationStore interface {
	SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord) error
	GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error)
	ListCommitVerificationByMessageID(ctx context.Context, committeeID string, messageID model.MessageID) ([]*model.CommitVerificationRecord, error)
}
