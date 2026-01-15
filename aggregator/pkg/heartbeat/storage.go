package heartbeat

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// DefaultKeyPrefix is the default Redis key prefix for heartbeat data.
	DefaultKeyPrefix = "heartbeat"
	// DefaultTTL is the default TTL for heartbeat data (7 days).
	DefaultTTL = 7 * 24 * time.Hour
)

// Storage defines the interface for storing and retrieving heartbeat data.
type Storage interface {
	// StoreBlockHeight stores the block height for a caller on a specific chain.
	StoreBlockHeight(ctx context.Context, callerID string, chainSelector uint64, blockHeight uint64) error
	// GetBlockHeights returns the block heights for all callers on a specific chain.
	GetBlockHeights(ctx context.Context, chainSelector uint64) (map[string]uint64, error)
	// GetMaxBlockHeight returns the maximum block height across all callers for a specific chain.
	GetMaxBlockHeight(ctx context.Context, chainSelector uint64) (uint64, error)
	// GetMaxBlockHeights returns the maximum block heights across all callers for multiple chains.
	GetMaxBlockHeights(ctx context.Context, chainSelectors []uint64) (map[uint64]uint64, error)
}

// RedisStorage implements Storage using Redis.
type RedisStorage struct {
	client    *redis.Client
	keyPrefix string
	ttl       time.Duration
}

// NewRedisStorage creates a new Redis-backed heartbeat storage.
func NewRedisStorage(client *redis.Client, keyPrefix string, ttl time.Duration) *RedisStorage {
	if keyPrefix == "" {
		keyPrefix = DefaultKeyPrefix
	}
	if ttl == 0 {
		ttl = DefaultTTL
	}
	return &RedisStorage{
		client:    client,
		keyPrefix: keyPrefix,
		ttl:       ttl,
	}
}

// StoreBlockHeight stores the block height for a caller on a specific chain.
func (s *RedisStorage) StoreBlockHeight(ctx context.Context, callerID string, chainSelector uint64, blockHeight uint64) error {
	key := s.buildKey(callerID, chainSelector)
	err := s.client.Set(ctx, key, blockHeight, s.ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store block height for caller %s chain %d: %w", callerID, chainSelector, err)
	}
	return nil
}

// GetBlockHeights returns the block heights for all callers on a specific chain.
func (s *RedisStorage) GetBlockHeights(ctx context.Context, chainSelector uint64) (map[string]uint64, error) {
	pattern := s.buildPattern(chainSelector)
	result := make(map[string]uint64)
	var cursor uint64

	for {
		// Scan for keys matching the pattern
		keys, nextCursor, err := s.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to scan keys for chain %d: %w", chainSelector, err)
		}

		// Get all values for the found keys
		if len(keys) > 0 {
			values, err := s.client.MGet(ctx, keys...).Result()
			if err != nil {
				return nil, fmt.Errorf("failed to get values for chain %d: %w", chainSelector, err)
			}

			// Parse keys to extract caller IDs and map to block heights
			for i, key := range keys {
				if values[i] == nil {
					continue
				}
				heightStr, ok := values[i].(string)
				if !ok {
					continue
				}
				height, err := strconv.ParseUint(heightStr, 10, 64)
				if err != nil {
					continue
				}

				// Extract caller ID from key (format: prefix:callerID:chainSelector)
				callerID := s.extractCallerID(key)
				if callerID != "" {
					result[callerID] = height
				}
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return result, nil
}

// GetMaxBlockHeight returns the maximum block height across all callers for a specific chain.
func (s *RedisStorage) GetMaxBlockHeight(ctx context.Context, chainSelector uint64) (uint64, error) {
	pattern := s.buildPattern(chainSelector)

	var maxHeight uint64
	var cursor uint64

	for {
		// Scan for keys matching the pattern
		keys, nextCursor, err := s.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return 0, fmt.Errorf("failed to scan keys for chain %d: %w", chainSelector, err)
		}

		// Get all values for the found keys
		if len(keys) > 0 {
			values, err := s.client.MGet(ctx, keys...).Result()
			if err != nil {
				return 0, fmt.Errorf("failed to get values for chain %d: %w", chainSelector, err)
			}

			// Find the maximum value
			for _, val := range values {
				if val == nil {
					continue
				}
				heightStr, ok := val.(string)
				if !ok {
					continue
				}
				height, err := strconv.ParseUint(heightStr, 10, 64)
				if err != nil {
					continue
				}
				if height > maxHeight {
					maxHeight = height
				}
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return maxHeight, nil
}

// GetMaxBlockHeights returns the maximum block heights across all callers for multiple chains.
func (s *RedisStorage) GetMaxBlockHeights(ctx context.Context, chainSelectors []uint64) (map[uint64]uint64, error) {
	result := make(map[uint64]uint64, len(chainSelectors))

	for _, chainSelector := range chainSelectors {
		maxHeight, err := s.GetMaxBlockHeight(ctx, chainSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to get max block height for chain %d: %w", chainSelector, err)
		}
		if maxHeight > 0 {
			result[chainSelector] = maxHeight
		}
	}

	return result, nil
}

// buildKey creates a Redis key for a specific caller and chain.
// Format: <prefix>:<caller_id>:<chain_selector>.
func (s *RedisStorage) buildKey(callerID string, chainSelector uint64) string {
	return fmt.Sprintf("%s:%s:%d", s.keyPrefix, callerID, chainSelector)
}

// buildPattern creates a Redis key pattern for scanning all callers on a specific chain.
// Format: <prefix>:*:<chain_selector>.
func (s *RedisStorage) buildPattern(chainSelector uint64) string {
	return fmt.Sprintf("%s:*:%d", s.keyPrefix, chainSelector)
}

// extractCallerID extracts the caller ID from a Redis key.
// Key format: <prefix>:<caller_id>:<chain_selector>.
func (s *RedisStorage) extractCallerID(key string) string {
	// Remove prefix
	prefixLen := len(s.keyPrefix) + 1 // +1 for the colon
	if len(key) <= prefixLen {
		return ""
	}
	remainder := key[prefixLen:]

	// Find the last colon to separate caller ID from chain selector
	lastColon := -1
	for i := len(remainder) - 1; i >= 0; i-- {
		if remainder[i] == ':' {
			lastColon = i
			break
		}
	}

	if lastColon == -1 {
		return ""
	}

	return remainder[:lastColon]
}

// InMemoryStorage implements Storage using in-memory maps with thread-safety.
type InMemoryStorage struct {
	mu sync.RWMutex
	// data maps "callerID:chainSelector" -> blockHeight
	data map[string]uint64
}

// NewInMemoryStorage creates a new in-memory heartbeat storage.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		data: make(map[string]uint64),
	}
}

// StoreBlockHeight stores the block height for a caller on a specific chain.
func (s *InMemoryStorage) StoreBlockHeight(ctx context.Context, callerID string, chainSelector uint64, blockHeight uint64) error {
	key := fmt.Sprintf("%s:%d", callerID, chainSelector)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.data[key] = blockHeight
	return nil
}

// GetBlockHeights returns the block heights for all callers on a specific chain.
func (s *InMemoryStorage) GetBlockHeights(ctx context.Context, chainSelector uint64) (map[string]uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]uint64)
	suffix := fmt.Sprintf(":%d", chainSelector)

	for key, height := range s.data {
		// Check if this key belongs to the requested chain
		if len(key) >= len(suffix) && key[len(key)-len(suffix):] == suffix {
			// Extract caller ID (everything before the suffix)
			callerID := key[:len(key)-len(suffix)]
			result[callerID] = height
		}
	}

	return result, nil
}

// GetMaxBlockHeight returns the maximum block height across all callers for a specific chain.
func (s *InMemoryStorage) GetMaxBlockHeight(ctx context.Context, chainSelector uint64) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var maxHeight uint64
	suffix := fmt.Sprintf(":%d", chainSelector)

	for key, height := range s.data {
		// Check if this key belongs to the requested chain
		if len(key) >= len(suffix) && key[len(key)-len(suffix):] == suffix {
			if height > maxHeight {
				maxHeight = height
			}
		}
	}

	return maxHeight, nil
}

// GetMaxBlockHeights returns the maximum block heights across all callers for multiple chains.
func (s *InMemoryStorage) GetMaxBlockHeights(ctx context.Context, chainSelectors []uint64) (map[uint64]uint64, error) {
	result := make(map[uint64]uint64, len(chainSelectors))

	for _, chainSelector := range chainSelectors {
		maxHeight, err := s.GetMaxBlockHeight(ctx, chainSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to get max block height for chain %d: %w", chainSelector, err)
		}
		if maxHeight > 0 {
			result[chainSelector] = maxHeight
		}
	}

	return result, nil
}

// NoopStorage is a no-op implementation of Storage.
type NoopStorage struct{}

// NewNoopStorage creates a new no-op storage.
func NewNoopStorage() *NoopStorage {
	return &NoopStorage{}
}

func (n *NoopStorage) StoreBlockHeight(ctx context.Context, callerID string, chainSelector uint64, blockHeight uint64) error {
	return nil
}

func (n *NoopStorage) GetBlockHeights(ctx context.Context, chainSelector uint64) (map[string]uint64, error) {
	return make(map[string]uint64), nil
}

func (n *NoopStorage) GetMaxBlockHeight(ctx context.Context, chainSelector uint64) (uint64, error) {
	return 0, nil
}

func (n *NoopStorage) GetMaxBlockHeights(ctx context.Context, chainSelectors []uint64) (map[uint64]uint64, error) {
	return make(map[uint64]uint64), nil
}
