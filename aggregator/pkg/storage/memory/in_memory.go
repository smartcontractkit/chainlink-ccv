// Package storage provides storage implementations for the aggregator service.
package memory

import (
	"bytes"
	"context"
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

// SaveCommitVerification persists a commit verification record.
func (s *InMemoryStorage) SaveCommitVerification(_ context.Context, record *model.CommitVerificationRecord) error {
	id, err := record.GetID()
	if err != nil {
		return err
	}

	s.records.Store(id.ToIdentifier(), record)
	return nil
}

// GetCommitVerification retrieves a commit verification record by its identifier.
func (s *InMemoryStorage) GetCommitVerification(_ context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	record, exists := s.records.Load(id.ToIdentifier())
	if !exists {
		return nil, errors.New("record not found")
	}

	castRecord, ok := record.(*model.CommitVerificationRecord)
	if !ok {
		return nil, errors.New("type assertion failed")
	}

	return castRecord, nil
}

// ListCommitVerificationByMessageID retrieves all commit verification records for a specific message ID.
func (s *InMemoryStorage) ListCommitVerificationByMessageID(_ context.Context, messageID model.MessageID, committee string) ([]*model.CommitVerificationRecord, error) {
	var results []*model.CommitVerificationRecord
	s.records.Range(func(key, value any) bool {
		if record, ok := value.(*model.CommitVerificationRecord); ok && bytes.Equal(record.MessageId, messageID) && record.CommitteeID == committee {
			results = append(results, record)
		}
		return true
	})
	return results, nil
}

func (s *InMemoryStorage) SubmitReport(_ context.Context, report *model.CommitAggregatedReport) error {
	id := report.GetID()
	report.Timestamp = time.Now().Unix()
	s.aggregatedReports.Store(id, report)
	return nil
}

func (s *InMemoryStorage) QueryAggregatedReports(_ context.Context, start, end int64, committeeID string, token *string) (*model.PaginatedAggregatedReports, error) {
	var results []*model.CommitAggregatedReport
	s.aggregatedReports.Range(func(key, value any) bool {
		if report, ok := value.(*model.CommitAggregatedReport); ok {
			if report.Timestamp >= start && report.Timestamp <= end && report.CommitteeID == committeeID {
				results = append(results, report)
			}
		}
		return true
	})
	return &model.PaginatedAggregatedReports{Reports: results}, nil
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

// ListOrphanedMessageIDs streams unique (messageID, committeeID) combinations that have verification records but no aggregated reports.
// Returns a channel for pairs and a channel for errors. Both channels will be closed when iteration is complete.
func (s *InMemoryStorage) ListOrphanedMessageIDs(ctx context.Context, committeeID model.CommitteeID) (<-chan model.MessageID, <-chan error) {
	pairCh := make(chan model.MessageID, 10) // Buffered for performance
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

			if record, ok := value.(*model.CommitVerificationRecord); ok {
				pairCh <- record.MessageId
			}
			return true
		})
	}()

	return pairCh, errCh
}

// NewInMemoryStorage creates a new instance of InMemoryStorage.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		records:           new(sync.Map),
		aggregatedReports: new(sync.Map),
	}
}
