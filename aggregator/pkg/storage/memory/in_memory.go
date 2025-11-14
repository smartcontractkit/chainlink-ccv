// Package storage provides storage implementations for the aggregator service.
package memory

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// InMemoryStorage is an in-memory implementation of the CommitVerificationStore interface.
type InMemoryStorage struct {
	records           *sync.Map
	aggregatedReports *sync.Map
	timeProvider      common.TimeProvider
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
func (s *InMemoryStorage) ListCommitVerificationByAggregationKey(_ context.Context, messageID model.MessageID, aggreationKey model.AggregationKey, committee string) ([]*model.CommitVerificationRecord, error) {
	recordMatch := func(r *recordWithAggregationKey) bool {
		if !bytes.Equal(r.record.MessageID, messageID) {
			return false
		}
		if r.record.CommitteeID != committee {
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

func (s *InMemoryStorage) SubmitReport(_ context.Context, report *model.CommitAggregatedReport) error {
	id := report.GetID()
	report.WrittenAt = s.timeProvider.Now()
	s.aggregatedReports.Store(id, report)
	return nil
}

func (s *InMemoryStorage) QueryAggregatedReportsRange(_ context.Context, start, end int64, committeeID string) (*model.AggregatedReportBatch, error) {
	var results []*model.CommitAggregatedReport
	s.aggregatedReports.Range(func(key, value any) bool {
		if report, ok := value.(*model.CommitAggregatedReport); ok {
			timestamp := report.WrittenAt.UnixMilli()
			if timestamp == 0 {
				timestamp = report.Sequence
			}
			if timestamp >= start && timestamp <= end && report.CommitteeID == committeeID {
				results = append(results, report)
			}
		}
		return true
	})
	return &model.AggregatedReportBatch{Reports: results}, nil
}

func (s *InMemoryStorage) QueryAggregatedReports(ctx context.Context, sinceSequenceInclusive int64, committeeID string) (*model.AggregatedReportBatch, error) {
	end := s.timeProvider.Now().UnixMilli()
	return s.QueryAggregatedReportsRange(ctx, sinceSequenceInclusive, end, committeeID)
}

func (s *InMemoryStorage) GetCCVData(_ context.Context, messageID model.MessageID, committeeID string) (*model.CommitAggregatedReport, error) {
	id := model.GetAggregatedReportID(messageID, committeeID)
	if value, ok := s.aggregatedReports.Load(id); ok {
		if report, ok := value.(*model.CommitAggregatedReport); ok && report.CommitteeID == committeeID {
			return report, nil
		}
	}
	return nil, nil
}

// GetBatchCCVData retrieves commit verification data for multiple message IDs.
func (s *InMemoryStorage) GetBatchCCVData(_ context.Context, messageIDs []model.MessageID, committeeID string) (map[string]*model.CommitAggregatedReport, error) {
	results := make(map[string]*model.CommitAggregatedReport)

	for _, messageID := range messageIDs {
		id := model.GetAggregatedReportID(messageID, committeeID)
		if value, ok := s.aggregatedReports.Load(id); ok {
			if report, ok := value.(*model.CommitAggregatedReport); ok && report.CommitteeID == committeeID {
				// Use hex encoding to match PostgreSQL implementation
				messageIDHex := hex.EncodeToString(messageID)
				results[messageIDHex] = report
			}
		}
	}

	return results, nil
}

// ListOrphanedMessageIDs streams unique (messageID, committeeID) combinations that have verification records but no aggregated reports.
// Returns a channel for pairs and a channel for errors. Both channels will be closed when iteration is complete.
func (s *InMemoryStorage) ListOrphanedKeys(ctx context.Context, committeeID model.CommitteeID) (<-chan model.OrphanedKey, <-chan error) {
	pairCh := make(chan model.OrphanedKey, 10) // Buffered for performance
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
				_, found := s.aggregatedReports.Load(model.GetAggregatedReportID(record.record.MessageID, committeeID))
				if !found {
					pairCh <- model.OrphanedKey{
						AggregationKey: record.aggregationKey,
						MessageID:      record.record.MessageID,
						CommitteeID:    committeeID,
					}
				}
			}
			return true
		})
	}()

	return pairCh, errCh
}

// NewInMemoryStorage creates a new instance of InMemoryStorage.
func NewInMemoryStorage() *InMemoryStorage {
	return NewInMemoryStorageWithTimeProvider(common.NewRealTimeProvider())
}

func NewInMemoryStorageWithTimeProvider(timeProvider common.TimeProvider) *InMemoryStorage {
	return &InMemoryStorage{
		records:           new(sync.Map),
		aggregatedReports: new(sync.Map),
		timeProvider:      timeProvider,
	}
}
