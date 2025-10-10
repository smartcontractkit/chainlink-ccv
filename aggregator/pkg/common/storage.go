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
	ListCommitVerificationByMessageID(ctx context.Context, messageID model.MessageID, committee string) ([]*model.CommitVerificationRecord, error)
	// ListOrphanedMessageIDs finds verification records that have not been aggregated yet.
	// Returns channels for streaming results: one for message/committee pairs, one for errors.
	ListOrphanedMessageIDs(ctx context.Context, committeeID model.CommitteeID) (<-chan model.MessageID, <-chan error)
}

type CommitVerificationAggregatedStore interface {
	// QueryAggregatedReports retrieves all aggregated reports within a specific time range.
	QueryAggregatedReports(ctx context.Context, start, end int64, committeeID string, token *string) (*model.PaginatedAggregatedReports, error)
	// GetCCVData retrieves the aggregated CCV data for a specific message ID.
	GetCCVData(ctx context.Context, messageID model.MessageID, committeeID string) (*model.CommitAggregatedReport, error)
}

// CheckpointStorageInterface defines the interface for checkpoint storage implementations.
type CheckpointStorageInterface interface {
	// StoreCheckpoints stores checkpoint data for a client.
	StoreCheckpoints(ctx context.Context, clientID string, checkpoints map[uint64]uint64) error
	// GetClientCheckpoints retrieves all checkpoints for a specific client.
	GetClientCheckpoints(ctx context.Context, clientID string) (map[uint64]uint64, error)
	// GetAllClients returns a list of all client IDs that have stored checkpoints.
	GetAllClients(ctx context.Context) ([]string, error)
}
