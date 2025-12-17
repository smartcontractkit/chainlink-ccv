// Package storage provides storage implementations for the aggregator service.
package memory

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// InMemoryStorage is an in-memory implementation of the CommitVerificationStore interface.
type InMemoryStorage struct {
	records           *sync.Map
	aggregatedReports *sync.Map
}

type recordWithAggregationKey struct {
	record         *model.CommitVerificationRecord
	aggregationKey model.AggregationKey
}

// SaveCommitVerification persists a commit verification record.
func (s *InMemoryStorage) SaveCommitVerification(_ context.Context, record *model.CommitVerificationRecord, aggregationKey model.AggregationKey) error {
	id, err := record.GetID()
	if err != nil {
		return err
	}

	r := recordWithAggregationKey{
		record,
		aggregationKey,
	}

	s.records.Store(id.ToIdentifier(), &r)
	return nil
}

// GetCommitVerification retrieves a commit verification record by its identifier.
func (s *InMemoryStorage) GetCommitVerification(_ context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	record, exists := s.records.Load(id.ToIdentifier())
	if !exists {
		return nil, errors.New("record not found")
	}

	castRecord, ok := record.(*recordWithAggregationKey)
	if !ok {
		return nil, errors.New("type assertion failed")
	}

	return castRecord.record, nil
}

// ListCommitVerificationByAggregationKey retrieves all commit verification records for a specific message ID.
func (s *InMemoryStorage) ListCommitVerificationByAggregationKey(_ context.Context, messageID model.MessageID, aggreationKey model.AggregationKey) ([]*model.CommitVerificationRecord, error) {
	recordMatch := func(r *recordWithAggregationKey) bool {
		if !bytes.Equal(r.record.MessageID, messageID) {
			return false
		}
		if r.aggregationKey != aggreationKey {
			return false
		}
		return true
	}

	var results []*model.CommitVerificationRecord
	s.records.Range(func(key, value any) bool {
		if recordWithAgg, ok := value.(*recordWithAggregationKey); ok && recordMatch(recordWithAgg) {
			results = append(results, recordWithAgg.record)
		}
		return true
	})
	return results, nil
}

func (s *InMemoryStorage) SubmitAggregatedReport(_ context.Context, report *model.CommitAggregatedReport) error {
	id := report.GetID()
	report.WrittenAt = time.Now()
	s.aggregatedReports.Store(id, report)
	return nil
}

func (s *InMemoryStorage) QueryAggregatedReportsRange(_ context.Context, start, end int64) (*model.AggregatedReportBatch, error) {
	var results []*model.CommitAggregatedReport
	s.aggregatedReports.Range(func(key, value any) bool {
		if report, ok := value.(*model.CommitAggregatedReport); ok {
			timestamp := report.WrittenAt.UnixMilli()
			if timestamp == 0 {
				timestamp = report.Sequence
			}
			if timestamp >= start && timestamp <= end {
				results = append(results, report)
			}
		}
		return true
	})
	return &model.AggregatedReportBatch{Reports: results}, nil
}

func (s *InMemoryStorage) QueryAggregatedReports(ctx context.Context, sinceSequenceInclusive int64) (*model.AggregatedReportBatch, error) {
	end := time.Now().UnixMilli()
	return s.QueryAggregatedReportsRange(ctx, sinceSequenceInclusive, end)
}

func (s *InMemoryStorage) GetCommitAggregatedReportByMessageID(_ context.Context, messageID model.MessageID) (*model.CommitAggregatedReport, error) {
	id := model.GetAggregatedReportID(messageID)
	if value, ok := s.aggregatedReports.Load(id); ok {
		if report, ok := value.(*model.CommitAggregatedReport); ok {
			return report, nil
		}
	}
	return nil, nil
}

// GetBatchAggregatedReportByMessageIDs retrieves commit verification data for multiple message IDs.
func (s *InMemoryStorage) GetBatchAggregatedReportByMessageIDs(_ context.Context, messageIDs []model.MessageID) (map[string]*model.CommitAggregatedReport, error) {
	results := make(map[string]*model.CommitAggregatedReport)

	for _, messageID := range messageIDs {
		id := model.GetAggregatedReportID(messageID)
		if value, ok := s.aggregatedReports.Load(id); ok {
			if report, ok := value.(*model.CommitAggregatedReport); ok {
				messageIDHex := hex.EncodeToString(messageID)
				results[messageIDHex] = report
			}
		}
	}

	return results, nil
}

// ListOrphanedKeys streams unique (messageID, aggregationKey) combinations that have verification records
// but no aggregated reports, and are newer than the given cutoff time.
// Returns a channel for pairs and a channel for errors. Both channels will be closed when iteration is complete.
func (s *InMemoryStorage) ListOrphanedKeys(ctx context.Context, newerThan time.Time) (<-chan model.OrphanedKey, <-chan error) {
	pairCh := make(chan model.OrphanedKey, 10)
	errCh := make(chan error, 1)

	go func() {
		defer close(pairCh)
		defer close(errCh)

		s.records.Range(func(key, value any) bool {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return false
			default:
			}

			if record, ok := value.(*recordWithAggregationKey); ok {
				_, found := s.aggregatedReports.Load(model.GetAggregatedReportID(record.record.MessageID))
				if !found && !record.record.GetTimestamp().Before(newerThan) {
					pairCh <- model.OrphanedKey{
						AggregationKey: record.aggregationKey,
						MessageID:      record.record.MessageID,
					}
				}
			}
			return true
		})
	}()

	return pairCh, errCh
}

// OrphanedKeyStats returns counts of orphaned records split by expired/non-expired status.
func (s *InMemoryStorage) OrphanedKeyStats(_ context.Context, cutoff time.Time) (*model.OrphanStats, error) {
	stats := &model.OrphanStats{}

	s.records.Range(func(key, value any) bool {
		if record, ok := value.(*recordWithAggregationKey); ok {
			_, found := s.aggregatedReports.Load(model.GetAggregatedReportID(record.record.MessageID))
			if !found {
				stats.TotalCount++
				if record.record.GetTimestamp().Before(cutoff) {
					stats.ExpiredCount++
				} else {
					stats.NonExpiredCount++
				}
			}
		}
		return true
	})

	return stats, nil
}

// DeleteExpiredOrphans deletes orphan verification records older than the given time.
// batchSize is accepted for interface compatibility but not used in the in-memory implementation.
// Returns channels for streaming deleted records and errors.
func (s *InMemoryStorage) DeleteExpiredOrphans(ctx context.Context, olderThan time.Time, _ int) (<-chan model.DeletedOrphan, <-chan error) {
	deletedCh := make(chan model.DeletedOrphan, 10)
	errCh := make(chan error, 1)

	go func() {
		defer close(deletedCh)
		defer close(errCh)

		var keysToDelete []any

		s.records.Range(func(key, value any) bool {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return false
			default:
			}

			if record, ok := value.(*recordWithAggregationKey); ok {
				_, hasAggregated := s.aggregatedReports.Load(model.GetAggregatedReportID(record.record.MessageID))
				if !hasAggregated && record.record.GetTimestamp().Before(olderThan) {
					keysToDelete = append(keysToDelete, key)
				}
			}
			return true
		})

		for _, key := range keysToDelete {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			default:
			}

			if value, ok := s.records.LoadAndDelete(key); ok {
				if record, ok := value.(*recordWithAggregationKey); ok {
					signerAddr := ""
					if record.record.IdentifierSigner != nil {
						signerAddr = hex.EncodeToString(record.record.IdentifierSigner.Address)
					}
					select {
					case deletedCh <- model.DeletedOrphan{
						MessageID:      record.record.MessageID,
						AggregationKey: record.aggregationKey,
						SignerAddress:  signerAddr,
					}:
					case <-ctx.Done():
						errCh <- ctx.Err()
						return
					}
				}
			}
		}
	}()

	return deletedCh, errCh
}

// NewInMemoryStorage creates a new instance of InMemoryStorage.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		records:           new(sync.Map),
		aggregatedReports: new(sync.Map),
	}
}
