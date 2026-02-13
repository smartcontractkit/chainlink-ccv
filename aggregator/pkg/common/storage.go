// Package common provides shared interfaces
package common

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// CommitVerificationStore defines an interface for storing and retrieving commit verification records.
type CommitVerificationStore interface {
	// SaveCommitVerification persists a commit verification record.
	SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord, aggregationKey model.AggregationKey) error
	// GetCommitVerification retrieves a commit verification record by its identifier.
	GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error)
	// ListCommitVerificationByAggregationKey retrieves all commit verification records for a specific message ID and aggregation Key.
	ListCommitVerificationByAggregationKey(ctx context.Context, messageID model.MessageID, aggregationKey model.AggregationKey) ([]*model.CommitVerificationRecord, error)
	// ListOrphanedKeys finds verification records that have not been aggregated yet and are newer than the cutoff.
	// Returns channels for streaming results: one for message pairs, one for errors.
	// pageSize controls the number of rows fetched per database page.
	ListOrphanedKeys(ctx context.Context, newerThan time.Time, pageSize int) (<-chan model.OrphanedKey, <-chan error)
	// OrphanedKeyStats returns counts of orphaned records split by expired/non-expired status.
	OrphanedKeyStats(ctx context.Context, cutoff time.Time) (*model.OrphanStats, error)
}

type CommitVerificationAggregatedStore interface {
	// QueryAggregatedReports retrieves a batch of aggregated reports starting from a sequence number.
	QueryAggregatedReports(ctx context.Context, sinceSequenceInclusive int64) (*model.AggregatedReportBatch, error)
	// GetCommitAggregatedReportByMessageID retrieves the aggregated CCV data for a specific message ID.
	GetCommitAggregatedReportByMessageID(ctx context.Context, messageID model.MessageID) (*model.CommitAggregatedReport, error)
	// GetBatchAggregatedReportByMessageIDs retrieves the aggregated CCV data for multiple message IDs efficiently.
	// Returns a map of messageID hex string to CommitAggregatedReport. Missing message IDs are not included in the map.
	GetBatchAggregatedReportByMessageIDs(ctx context.Context, messageIDs []model.MessageID) (map[string]*model.CommitAggregatedReport, error)
}
