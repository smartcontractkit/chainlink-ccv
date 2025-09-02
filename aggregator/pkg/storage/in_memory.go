package storage

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// InMemoryStorage is an in-memory implementation of the CommitVerificationStore interface.
type InMemoryStorage struct {
	records map[string]*model.CommitVerificationRecord
}

// SaveCommitVerification persists a commit verification record.
func (s *InMemoryStorage) SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord) error {
	id := record.GetID()
	s.records[id.ToIdentifier()] = record
	return nil
}

// GetCommitVerification retrieves a commit verification record by its identifier.
func (s *InMemoryStorage) GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	record, exists := s.records[id.ToIdentifier()]
	if !exists {
		return nil, fmt.Errorf("record not found")
	}
	return record, nil
}

// ListCommitVerificationByMessageID retrieves all commit verification records for a specific message ID and committee ID.
func (s *InMemoryStorage) ListCommitVerificationByMessageID(ctx context.Context, committeeID string, messageID model.MessageID) ([]*model.CommitVerificationRecord, error) {
	var results []*model.CommitVerificationRecord
	for _, record := range s.records {
		if record.CommitteeID == committeeID && record.MessageId == messageID {
			results = append(results, record)
		}
	}
	return results, nil
}

// NewInMemoryStorage creates a new instance of InMemoryStorage.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		records: make(map[string]*model.CommitVerificationRecord),
	}
}
