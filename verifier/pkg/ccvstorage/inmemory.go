package ccvstorage

import (
	"context"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var _ CCVStorage = &InMemoryCCVStorage{}

type InMemoryCCVStorage struct {
	mu   sync.RWMutex
	data map[protocol.Bytes32]Entry
}

func NewInMemory() *InMemoryCCVStorage {
	return &InMemoryCCVStorage{
		data: make(map[protocol.Bytes32]Entry),
		mu:   sync.RWMutex{},
	}
}

func (s *InMemoryCCVStorage) Get(_ context.Context, key []protocol.Bytes32) (map[protocol.Bytes32]Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[protocol.Bytes32]Entry)
	for _, k := range key {
		if entry, exists := s.data[k]; exists {
			result[k] = entry
		}
	}
	return result, nil
}

func (s *InMemoryCCVStorage) Set(_ context.Context, entries []Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range entries {
		msgID, err := entry.Value.Message.MessageID()
		if err != nil {
			return err
		}
		s.data[msgID] = entry
	}
	return nil
}
