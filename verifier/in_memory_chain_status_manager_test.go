package verifier

import (
	"context"
	"math/big"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// InMemoryChainStatusManager is an in-memory implementation of ChainStatusManager for testing.
type InMemoryChainStatusManager struct {
	statuses map[protocol.ChainSelector]*protocol.ChainStatusInfo
	mu       sync.RWMutex
}

// NewInMemoryChainStatusManager creates a new in-memory chain status manager.
func NewInMemoryChainStatusManager() *InMemoryChainStatusManager {
	return &InMemoryChainStatusManager{
		statuses: make(map[protocol.ChainSelector]*protocol.ChainStatusInfo),
	}
}

// WriteChainStatus writes chain statuses for multiple chains atomically.
func (m *InMemoryChainStatusManager) WriteChainStatus(ctx context.Context, statuses []protocol.ChainStatusInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, status := range statuses {
		// Make a copy of the BlockHeight to avoid sharing pointers
		blockHeight := new(big.Int)
		if status.BlockHeight != nil {
			blockHeight.Set(status.BlockHeight)
		}

		m.statuses[status.ChainSelector] = &protocol.ChainStatusInfo{
			ChainSelector: status.ChainSelector,
			BlockHeight:   blockHeight,
			Disabled:      status.Disabled,
		}
	}
	return nil
}

// ReadChainStatus reads chain statuses for multiple chains.
// Returns map of chainSelector -> ChainStatusInfo. Missing chains are not included in the map.
func (m *InMemoryChainStatusManager) ReadChainStatus(ctx context.Context, chainSelectors []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[protocol.ChainSelector]*protocol.ChainStatusInfo)
	for _, selector := range chainSelectors {
		if status, ok := m.statuses[selector]; ok {
			// Return a copy to prevent external modification
			blockHeight := new(big.Int)
			if status.BlockHeight != nil {
				blockHeight.Set(status.BlockHeight)
			}

			result[selector] = &protocol.ChainStatusInfo{
				ChainSelector: status.ChainSelector,
				BlockHeight:   blockHeight,
				Disabled:      status.Disabled,
			}
		}
	}
	return result, nil
}
