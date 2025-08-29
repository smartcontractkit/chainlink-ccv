package storage

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

type InMemoryStorage struct {
	records map[string]*model.CommitVerificationRecord
}

func (s *InMemoryStorage) SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord) error {
	id := record.GetID()
	s.records[id.ToIdentifier()] = record
	return nil
}

func (s *InMemoryStorage) GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	record, exists := s.records[id.ToIdentifier()]
	if !exists {
		return nil, fmt.Errorf("record not found")
	}
	return record, nil
}

func (s *InMemoryStorage) ListCommitVerificationByMessageID(ctx context.Context, committeeID string, messageID model.MessageID) ([]*model.CommitVerificationRecord, error) {
	var results []*model.CommitVerificationRecord
	for _, record := range s.records {
		if record.CommitteeID == committeeID && record.MessageId == messageID {
			results = append(results, record)
		}
	}
	return results, nil
}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		records: make(map[string]*model.CommitVerificationRecord),
	}
}
