package memory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
)

// ChainStatusStorage provides thread-safe in-memory storage for blockchain chain status
// isolated by client API key.
type ChainStatusStorage struct {
	clientData sync.Map // map[string]*ClientChainStatus
}

// Ensure ChainStatusStorage implements the interface.
var _ common.ChainStatusStorageInterface = (*ChainStatusStorage)(nil)

// ClientChainStatus holds chain status data for a single client with thread-safe access.
type ClientChainStatus struct {
	lastUpdated time.Time
	statuses    map[uint64]*common.ChainStatus // chain_selector -> ChainStatus
	mu          sync.RWMutex
}

// NewChainStatusStorage creates a new instance of ChainStatusStorage.
func NewChainStatusStorage() *ChainStatusStorage {
	return &ChainStatusStorage{
		clientData: sync.Map{},
	}
}

// NewClientChainStatus creates a new instance of ClientChainStatus.
func NewClientChainStatus() *ClientChainStatus {
	return &ClientChainStatus{
		statuses: make(map[uint64]*common.ChainStatus),
	}
}

// StoreChainStatus stores a batch of statuses for a client atomically.
// If the client doesn't exist, it will be created.
// Existing statuses for the same chain_selector will be overridden.
func (s *ChainStatusStorage) StoreChainStatus(ctx context.Context, clientID string, statuses map[uint64]*common.ChainStatus) error {
	if err := validateStoreChainStatusInput(clientID, statuses); err != nil {
		return err
	}

	// Get or create client storage
	value, _ := s.clientData.LoadOrStore(clientID, NewClientChainStatus())
	clientStore, ok := value.(*ClientChainStatus)
	if !ok {
		return fmt.Errorf("invalid client storage type for client %s", clientID)
	}

	// Store statuses atomically
	clientStore.StoreChainStatus(ctx, statuses)

	return nil
}

// GetClientChainStatus retrieves all statuses for a client.
// Returns an empty map if the client has no statuses.
func (s *ChainStatusStorage) GetClientChainStatus(ctx context.Context, clientID string) (map[uint64]*common.ChainStatus, error) {
	value, exists := s.clientData.Load(clientID)
	if !exists {
		return make(map[uint64]*common.ChainStatus), nil
	}

	clientStore, ok := value.(*ClientChainStatus)
	if !ok {
		return make(map[uint64]*common.ChainStatus), nil
	}
	return clientStore.GetChainStatus(ctx), nil
}

// StoreChainStatus stores statuses for this client atomically.
func (c *ClientChainStatus) StoreChainStatus(ctx context.Context, statuses map[uint64]*common.ChainStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Store all statuses (overriding existing ones)
	for chainSelector, chainStatus := range statuses {
		c.statuses[chainSelector] = chainStatus
	}

	c.lastUpdated = time.Now()
}

// GetChainStatus returns a copy of all statuses for this client.
func (c *ClientChainStatus) GetChainStatus(ctx context.Context) map[uint64]*common.ChainStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy to prevent concurrent modification
	result := make(map[uint64]*common.ChainStatus, len(c.statuses))
	for chainSelector, chainStatus := range c.statuses {
		result[chainSelector] = chainStatus
	}

	return result
}

// GetLastUpdated returns the timestamp of the last update.
func (c *ClientChainStatus) GetLastUpdated() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.lastUpdated
}

// validateStoreChainStatusInput validates the input parameters for StoreChainStatus.
func validateStoreChainStatusInput(clientID string, statuses map[uint64]*common.ChainStatus) error {
	if strings.TrimSpace(clientID) == "" {
		return errors.New("client ID cannot be empty")
	}

	if statuses == nil {
		return errors.New("statuses cannot be nil")
	}

	// Validate each status
	for chainSelector, chainStatus := range statuses {
		if chainSelector == 0 {
			return errors.New("chain_selector must be greater than 0")
		}
		if chainStatus == nil {
			return errors.New("chain status cannot be nil")
		}
		if chainStatus.FinalizedBlockHeight == 0 {
			return errors.New("finalized_block_height must be greater than 0")
		}
	}

	return nil
}

// GetAllClients returns a list of all client IDs that have stored statuses.
// This is primarily for testing and debugging purposes.
func (s *ChainStatusStorage) GetAllClients(ctx context.Context) ([]string, error) {
	var clients []string

	s.clientData.Range(func(key, value any) bool {
		clientID, ok := key.(string)
		if !ok {
			return true // skip invalid entries
		}
		clients = append(clients, clientID)
		return true
	})

	return clients, nil
}
