// Package storage provides storage implementations for the aggregator service.
package storage

import (
	"bytes"
	"context"
	"errors"
	"sync"

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
	s.aggregatedReports.Store(id, report)
	return nil
}

func (s *InMemoryStorage) QueryAggregatedReports(_ context.Context, start, end int64, committeeID string) ([]*model.CommitAggregatedReport, error) {
	var results []*model.CommitAggregatedReport
	s.aggregatedReports.Range(func(key, value any) bool {
		if report, ok := value.(*model.CommitAggregatedReport); ok {
			if report.Timestamp >= start && report.Timestamp <= end && report.CommitteeID == committeeID {
				results = append(results, report)
			}
		}
		return true
	})
	return results, nil
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

// NewInMemoryStorage creates a new instance of InMemoryStorage.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		records:           new(sync.Map),
		aggregatedReports: new(sync.Map),
	}
}
