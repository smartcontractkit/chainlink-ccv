package middlewares

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

func TestNewRateLimiterStore_Memory(t *testing.T) {
	t.Run("creates memory store successfully", func(t *testing.T) {
		config := model.RateLimiterStoreConfig{
			Type: model.RateLimiterStoreTypeMemory,
		}

		store, err := NewRateLimiterStore(config)
		require.NoError(t, err)
		require.NotNil(t, store)
	})

	t.Run("creates memory store when type is empty", func(t *testing.T) {
		config := model.RateLimiterStoreConfig{}

		store, err := NewRateLimiterStore(config)
		require.NoError(t, err)
		require.NotNil(t, store)
	})
}

func TestNewRateLimiterStore_Redis(t *testing.T) {
	t.Run("fails when redis address is missing", func(t *testing.T) {
		config := model.RateLimiterStoreConfig{
			Type: model.RateLimiterStoreTypeRedis,
		}

		store, err := NewRateLimiterStore(config)
		require.Error(t, err)
		require.Nil(t, store)
		require.Contains(t, err.Error(), "redis configuration is required")
	})

	t.Run("fails when redis is unreachable", func(t *testing.T) {
		config := model.RateLimiterStoreConfig{
			Type: model.RateLimiterStoreTypeRedis,
			Redis: &model.RateLimiterRedisConfig{
				Address: "localhost:9999", // Invalid port
			},
		}

		store, err := NewRateLimiterStore(config)
		require.Error(t, err)
		require.Nil(t, store)
		require.Contains(t, err.Error(), "failed to connect to redis")
	})

	t.Run("fails when redis address is empty in nested config", func(t *testing.T) {
		config := model.RateLimiterStoreConfig{
			Type: model.RateLimiterStoreTypeRedis,
			Redis: &model.RateLimiterRedisConfig{
				Address: "", // Empty address
			},
		}

		store, err := NewRateLimiterStore(config)
		require.Error(t, err)
		require.Nil(t, store)
		require.Contains(t, err.Error(), "redis address is required")
	})
}

func TestNewRateLimiterStore_InvalidType(t *testing.T) {
	config := model.RateLimiterStoreConfig{
		Type: "invalid",
	}

	store, err := NewRateLimiterStore(config)
	require.Error(t, err)
	require.Nil(t, store)
	require.Contains(t, err.Error(), "unsupported storage type")
}
