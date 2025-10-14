package middlewares

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

	r "github.com/ulule/limiter/v3/drivers/store/redis"
)

// NewRateLimiterStore creates a new rate limiter store based on the configuration.
func NewRateLimiterStore(config model.RateLimiterStoreConfig) (limiter.Store, error) {
	switch config.Type {
	case model.RateLimiterStoreTypeMemory, "":
		return memory.NewStore(), nil

	case model.RateLimiterStoreTypeRedis:
		if config.Redis == nil {
			return nil, fmt.Errorf("redis configuration is required when using redis storage")
		}

		if config.Redis.Address == "" {
			return nil, fmt.Errorf("redis address is required when using redis storage")
		}

		redisClient := redis.NewClient(&redis.Options{
			Addr:     config.Redis.Address,
			Password: config.Redis.Password,
			DB:       config.Redis.DB,
		})

		if err := redisClient.Ping(context.Background()).Err(); err != nil {
			return nil, fmt.Errorf("failed to connect to redis at %s: %w", config.Redis.Address, err)
		}

		keyPrefix := config.Redis.KeyPrefix
		if keyPrefix == "" {
			keyPrefix = model.DefaultRateLimiterRedisKeyPrefix
		}

		store, err := r.NewStoreWithOptions(redisClient, limiter.StoreOptions{
			Prefix:          keyPrefix,
			CleanUpInterval: 1 * time.Minute,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create redis store: %w", err)
		}

		return store, nil

	default:
		return nil, fmt.Errorf("unsupported storage type: %s (supported: %s, %s)", config.Type, model.RateLimiterStoreTypeMemory, model.RateLimiterStoreTypeRedis)
	}
}
