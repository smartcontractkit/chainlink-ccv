package storage

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// CheckpointStorage provides thread-safe storage for blockchain checkpoints
// isolated by client API key.
type CheckpointStorage struct {
	clientData sync.Map // map[string]*ClientCheckpoints
}

// ClientCheckpoints holds checkpoint data for a single client with thread-safe access.
type ClientCheckpoints struct {
	mu          sync.RWMutex
	checkpoints map[uint64]uint64 // chain_selector -> finalized_block_height
	lastUpdated time.Time
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
func (s *CheckpointStorage) StoreCheckpoints(clientID string, checkpoints map[uint64]uint64) error {
	if err := validateStoreCheckpointsInput(clientID, checkpoints); err != nil {
		return err
	}

	// Get or create client storage
	value, _ := s.clientData.LoadOrStore(clientID, NewClientCheckpoints())
	clientStore := value.(*ClientCheckpoints)

	// Store checkpoints atomically
	clientStore.StoreCheckpoints(checkpoints)

	return nil
}

// GetClientCheckpoints retrieves all checkpoints for a client.
// Returns an empty map if the client has no checkpoints.
func (s *CheckpointStorage) GetClientCheckpoints(clientID string) map[uint64]uint64 {
	value, exists := s.clientData.Load(clientID)
	if !exists {
		return make(map[uint64]uint64)
	}

	clientStore := value.(*ClientCheckpoints)
	return clientStore.GetCheckpoints()
}

// StoreCheckpoints stores checkpoints for this client atomically.
func (c *ClientCheckpoints) StoreCheckpoints(checkpoints map[uint64]uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Store all checkpoints (overriding existing ones)
	for chainSelector, blockHeight := range checkpoints {
		c.checkpoints[chainSelector] = blockHeight
	}

	c.lastUpdated = time.Now()
}

// GetCheckpoints returns a copy of all checkpoints for this client.
func (c *ClientCheckpoints) GetCheckpoints() map[uint64]uint64 {
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
func (s *CheckpointStorage) GetAllClients() []string {
	var clients []string

	s.clientData.Range(func(key, value interface{}) bool {
		clientID := key.(string)
		clients = append(clients, clientID)
		return true
	})

	return clients
}

// GetStorageStats returns statistics about the storage for monitoring.
func (s *CheckpointStorage) GetStorageStats() StorageStats {
	stats := StorageStats{}

	s.clientData.Range(func(key, value interface{}) bool {
		clientStore := value.(*ClientCheckpoints)
		clientStore.mu.RLock()
		stats.TotalClients++
		stats.TotalCheckpoints += len(clientStore.checkpoints)
		if clientStore.lastUpdated.After(stats.LastUpdate) {
			stats.LastUpdate = clientStore.lastUpdated
		}
		clientStore.mu.RUnlock()
		return true
	})

	return stats
}

// StorageStats provides statistics about checkpoint storage usage.
type StorageStats struct {
	TotalClients     int
	TotalCheckpoints int
	LastUpdate       time.Time
}

func (s StorageStats) String() string {
	return fmt.Sprintf("CheckpointStorage{clients: %d, checkpoints: %d, last_update: %v}",
		s.TotalClients, s.TotalCheckpoints, s.LastUpdate)
}
