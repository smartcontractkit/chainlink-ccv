package storage

import (
	"context"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type InMemory struct {
	mu   sync.RWMutex
	data map[protocol.Bytes32]Entry
}

func NewInMemory() *InMemory {
	return &InMemory{
		data: make(map[protocol.Bytes32]Entry),
		mu:   sync.RWMutex{},
	}
}

type Entry struct {
	value                 protocol.VerifierNodeResult
	verifierSourceAddress protocol.UnknownAddress
	verifierDestAddress   protocol.UnknownAddress
	timestamp             time.Time
}

func (s *InMemory) Get(_ context.Context, key []protocol.Bytes32) map[protocol.Bytes32]Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[protocol.Bytes32]Entry)
	for _, k := range key {
		if entry, exists := s.data[k]; exists {
			result[k] = entry
		}
	}
	return result
}

func (s *InMemory) Set(_ context.Context, entries []Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range entries {
		msgID, err := entry.value.Message.MessageID()
		if err != nil {
			return err
		}
		s.data[msgID] = entry
	}
	return nil
}
