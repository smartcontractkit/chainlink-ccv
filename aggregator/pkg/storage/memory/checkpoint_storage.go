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

// CheckpointStorage provides thread-safe in-memory storage for blockchain checkpoints
// isolated by client API key.
type CheckpointStorage struct {
	clientData sync.Map // map[string]*ClientCheckpoints
}

// Ensure CheckpointStorage implements the interface.
var _ common.CheckpointStorageInterface = (*CheckpointStorage)(nil)

// ClientCheckpoints holds checkpoint data for a single client with thread-safe access.
type ClientCheckpoints struct {
	lastUpdated time.Time
	checkpoints map[uint64]uint64 // chain_selector -> finalized_block_height
	mu          sync.RWMutex
}

// NewCheckpointStorage creates a new instance of CheckpointStorage.
func NewCheckpointStorage() *CheckpointStorage {
	return &CheckpointStorage{
		clientData: sync.Map{},
	}
}

// NewClientCheckpoints creates a new instance of ClientCheckpoints.
func NewClientCheckpoints() *ClientCheckpoints {
	return &ClientCheckpoints{
		checkpoints: make(map[uint64]uint64),
	}
}

// StoreCheckpoints stores a batch of checkpoints for a client atomically.
// If the client doesn't exist, it will be created.
// Existing checkpoints for the same chain_selector will be overridden.
func (s *CheckpointStorage) StoreCheckpoints(ctx context.Context, clientID string, checkpoints map[uint64]uint64) error {
	if err := validateStoreCheckpointsInput(clientID, checkpoints); err != nil {
		return err
	}

	// Get or create client storage
	value, _ := s.clientData.LoadOrStore(clientID, NewClientCheckpoints())
	clientStore, ok := value.(*ClientCheckpoints)
	if !ok {
		return fmt.Errorf("invalid client storage type for client %s", clientID)
	}

	// Store checkpoints atomically
	clientStore.StoreCheckpoints(ctx, checkpoints)

	return nil
}

// GetClientCheckpoints retrieves all checkpoints for a client.
// Returns an empty map if the client has no checkpoints.
func (s *CheckpointStorage) GetClientCheckpoints(ctx context.Context, clientID string) (map[uint64]uint64, error) {
	value, exists := s.clientData.Load(clientID)
	if !exists {
		return make(map[uint64]uint64), nil
	}

	clientStore, ok := value.(*ClientCheckpoints)
	if !ok {
		return make(map[uint64]uint64), nil
	}
	return clientStore.GetCheckpoints(ctx), nil
}

// StoreCheckpoints stores checkpoints for this client atomically.
func (c *ClientCheckpoints) StoreCheckpoints(ctx context.Context, checkpoints map[uint64]uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Store all checkpoints (overriding existing ones)
	for chainSelector, blockHeight := range checkpoints {
		c.checkpoints[chainSelector] = blockHeight
	}

	c.lastUpdated = time.Now()
}

// GetCheckpoints returns a copy of all checkpoints for this client.
func (c *ClientCheckpoints) GetCheckpoints(ctx context.Context) map[uint64]uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy to prevent concurrent modification
	result := make(map[uint64]uint64, len(c.checkpoints))
	for chainSelector, blockHeight := range c.checkpoints {
		result[chainSelector] = blockHeight
	}

	return result
}

// GetLastUpdated returns the timestamp of the last update.
func (c *ClientCheckpoints) GetLastUpdated() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.lastUpdated
}

// validateStoreCheckpointsInput validates the input parameters for StoreCheckpoints.
func validateStoreCheckpointsInput(clientID string, checkpoints map[uint64]uint64) error {
	if strings.TrimSpace(clientID) == "" {
		return errors.New("client ID cannot be empty")
	}

	if checkpoints == nil {
		return errors.New("checkpoints cannot be nil")
	}

	// Validate each checkpoint
	for chainSelector, blockHeight := range checkpoints {
		if chainSelector == 0 {
			return errors.New("chain_selector must be greater than 0")
		}
		if blockHeight == 0 {
			return errors.New("finalized_block_height must be greater than 0")
		}
	}

	return nil
}

// GetAllClients returns a list of all client IDs that have stored checkpoints.
// This is primarily for testing and debugging purposes.
func (s *CheckpointStorage) GetAllClients(ctx context.Context) ([]string, error) {
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
