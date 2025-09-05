// Package storage provides storage implementations for the aggregator service.
package storage

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// InMemoryStorage is an in-memory implementation of the CommitVerificationStore interface.
type InMemoryStorage struct {
	records           map[string]*model.CommitVerificationRecord
	aggregatedReports map[string]*model.CommitAggregatedReport
}

// SaveCommitVerification persists a commit verification record.
func (s *InMemoryStorage) SaveCommitVerification(_ context.Context, record *model.CommitVerificationRecord) error {
	id := record.GetID()
	s.records[id.ToIdentifier()] = record
	return nil
}

// GetCommitVerification retrieves a commit verification record by its identifier.
func (s *InMemoryStorage) GetCommitVerification(_ context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	record, exists := s.records[id.ToIdentifier()]
	if !exists {
		return nil, errors.New("record not found")
	}
	return record, nil
}

// ListCommitVerificationByMessageID retrieves all commit verification records for a specific message ID.
func (s *InMemoryStorage) ListCommitVerificationByMessageID(_ context.Context, messageID model.MessageID) ([]*model.CommitVerificationRecord, error) {
	var results []*model.CommitVerificationRecord
	for _, record := range s.records {
		if bytes.Equal(record.MessageId, messageID) {
			results = append(results, record)
		}
	}
	return results, nil
}

func (s *InMemoryStorage) SubmitReport(_ context.Context, report *model.CommitAggregatedReport) error {
	id := hex.EncodeToString(report.MessageID)
	s.aggregatedReports[id] = report
	return nil
}

func (s *InMemoryStorage) QueryAggregatedReports(_ context.Context, start, end int64) []*model.CommitAggregatedReport {
	var results []*model.CommitAggregatedReport
	for _, report := range s.aggregatedReports {
		if report.Timestamp >= start && report.Timestamp <= end {
			results = append(results, report)
		}
	}
	return results
}

func (s *InMemoryStorage) GetCCVData(_ context.Context, messageID model.MessageID) *model.CommitAggregatedReport {
	id := hex.EncodeToString(messageID)
	return s.aggregatedReports[id]
}

// NewInMemoryStorage creates a new instance of InMemoryStorage.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		records:           make(map[string]*model.CommitVerificationRecord),
		aggregatedReports: make(map[string]*model.CommitAggregatedReport),
	}
}
