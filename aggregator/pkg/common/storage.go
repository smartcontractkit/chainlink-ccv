// Package common provides shared interfaces
package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// CommitVerificationStore defines an interface for storing and retrieving commit verification records.
type CommitVerificationStore interface {
	// SaveCommitVerification persists a commit verification record.
	SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord) error
	// GetCommitVerification retrieves a commit verification record by its identifier.
	GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error)
	// ListCommitVerificationByMessageID retrieves all commit verification records for a specific message ID and committee ID.
	ListCommitVerificationByMessageID(ctx context.Context, messageID model.MessageID) ([]*model.CommitVerificationRecord, error)
}

type CommitVerificationAggregatedStore interface {
	// QueryAggregatedReports retrieves all aggregated reports within a specific time range.
	QueryAggregatedReports(ctx context.Context, start, end int64) []*model.CommitAggregatedReport
	// GetCCVData retrieves the aggregated CCV data for a specific message ID.
	GetCCVData(ctx context.Context, messageID model.MessageID) *model.CommitAggregatedReport
}
