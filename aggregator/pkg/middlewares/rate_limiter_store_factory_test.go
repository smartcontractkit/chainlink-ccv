package middlewares

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

func TestNewRateLimiterStore_Memory(t *testing.T) {
	ctx := context.Background()

	t.Run("creates memory store successfully", func(t *testing.T) {
		config := model.RateLimiterStoreConfig{
			Type: "memory",
		}

		store, err := NewRateLimiterStore(ctx, config)
		require.NoError(t, err)
		require.NotNil(t, store)
	})

	t.Run("creates memory store when type is empty", func(t *testing.T) {
		config := model.RateLimiterStoreConfig{}

		store, err := NewRateLimiterStore(ctx, config)
		require.NoError(t, err)
		require.NotNil(t, store)
	})
}

func TestNewRateLimiterStore_Redis(t *testing.T) {
	ctx := context.Background()

	t.Run("fails when redis address is missing", func(t *testing.T) {
		config := model.RateLimiterStoreConfig{
			Type: "redis",
		}

		store, err := NewRateLimiterStore(ctx, config)
		require.Error(t, err)
		require.Nil(t, store)
		require.Contains(t, err.Error(), "redis_address is required")
	})

	t.Run("fails when redis is unreachable", func(t *testing.T) {
		config := model.RateLimiterStoreConfig{
			Type:         "redis",
			RedisAddress: "localhost:9999", // Invalid port
		}

		store, err := NewRateLimiterStore(ctx, config)
		require.Error(t, err)
		require.Nil(t, store)
		require.Contains(t, err.Error(), "failed to connect to redis")
	})
}

func TestNewRateLimiterStore_InvalidType(t *testing.T) {
	ctx := context.Background()

	config := model.RateLimiterStoreConfig{
		Type: "invalid",
	}

	store, err := NewRateLimiterStore(ctx, config)
	require.Error(t, err)
	require.Nil(t, store)
	require.Contains(t, err.Error(), "unsupported storage type")
}
