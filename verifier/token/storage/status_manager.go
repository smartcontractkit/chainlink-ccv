package storage

import (
	"context"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type ChainStatusManager struct {
	mu       sync.RWMutex
	statuses map[protocol.ChainSelector]*protocol.ChainStatusInfo
}

func NewChainStatusManager() protocol.ChainStatusManager {
	return &ChainStatusManager{
		mu:       sync.RWMutex{},
		statuses: make(map[protocol.ChainSelector]*protocol.ChainStatusInfo),
	}
}

func (c *ChainStatusManager) WriteChainStatuses(
	_ context.Context,
	statuses []protocol.ChainStatusInfo,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, status := range statuses {
		c.statuses[status.ChainSelector] = &status
	}
	return nil
}

func (c *ChainStatusManager) ReadChainStatuses(
	_ context.Context,
	chainSelectors []protocol.ChainSelector,
) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[protocol.ChainSelector]*protocol.ChainStatusInfo)
	for _, selector := range chainSelectors {
		if status, exists := c.statuses[selector]; exists {
			result[selector] = status
		}
	}
	return result, nil
}
