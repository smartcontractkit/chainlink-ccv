// Package common provides shared interfaces
package common

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// CommitVerificationStore defines an interface for storing and retrieving commit verification records.
type CommitVerificationStore interface {
	// SaveCommitVerification persists a verification record. Idempotent on (message_id, signer_identifier,
	// aggregation_key); a new aggregation key for the same signer creates a separate row.
	SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord, aggregationKey model.AggregationKey) error
	// GetCommitVerification returns the latest verification record for a (message_id, signer_identifier)
	// pair across all aggregation keys.
	GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error)
	// ListCommitVerificationByAggregationKey returns the latest verification record per signer for a
	// given (message_id, aggregation_key). Used to collect quorum inputs before aggregation.
	ListCommitVerificationByAggregationKey(ctx context.Context, messageID model.MessageID, aggregationKey model.AggregationKey) ([]*model.CommitVerificationRecord, error)
	// ListOrphanedKeys streams (message_id, aggregation_key) pairs that have verification records but
	// no matching aggregated report. Joins on both columns so a CCV version change correctly surfaces
	// the new key as orphaned even when a report exists for the old key.
	ListOrphanedKeys(ctx context.Context, newerThan time.Time, pageSize int) (<-chan model.OrphanedKey, <-chan error)
	// OrphanedKeyStats returns aggregate counts of orphaned (message_id, aggregation_key) pairs
	// split by a cutoff time, for monitoring the orphan recovery process.
	OrphanedKeyStats(ctx context.Context, cutoff time.Time) (*model.OrphanStats, error)
}

// CommitVerificationAggregatedStore defines an interface for storing and retrieving aggregated reports.
type CommitVerificationAggregatedStore interface {
	// QueryAggregatedReports paginates through all aggregated reports from a sequence number.
	// No deduplication: multiple reports for the same (message_id, aggregation_key) are all returned.
	QueryAggregatedReports(ctx context.Context, sinceSequenceInclusive int64) (*model.AggregatedReportBatch, error)
	// GetCommitAggregatedReportByAggregationKey returns the latest aggregated report for a specific
	// (message_id, aggregation_key) pair. Returns ErrNotFound when no report exists.
	GetCommitAggregatedReportByAggregationKey(ctx context.Context, messageID model.MessageID, aggregationKey model.AggregationKey) (*model.CommitAggregatedReport, error)
	// GetBatchAggregatedReportByMessageIDs returns the latest aggregated report per message ID across
	// all aggregation keys. The result map is keyed by hex-encoded message ID; missing IDs are omitted.
	GetBatchAggregatedReportByMessageIDs(ctx context.Context, messageIDs []model.MessageID) (map[string]*model.CommitAggregatedReport, error)
}
