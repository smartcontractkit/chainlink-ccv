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
}

type CommitVerificationAggregatedStore interface {
	// QueryAggregatedReports retrieves aggregated reports within a specific time range with pagination support.
	// Parameters:
	//   - start, end: Unix timestamp range for filtering reports
	//   - committeeID: Committee identifier for filtering
	//   - limit: Maximum number of records to return (server-controlled)
	//   - lastSeqNum: Sequence number of the last record from previous page (nil for first page)
	// Returns paginated response with reports and metadata for next page generation.
	QueryAggregatedReports(ctx context.Context, start, end int64, committeeID string, limit int, lastSeqNum *int64) (*model.PaginatedAggregatedReportsResponse, error)
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
