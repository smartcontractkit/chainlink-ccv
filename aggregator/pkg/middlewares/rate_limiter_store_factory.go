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
func NewRateLimiterStore(ctx context.Context, config model.RateLimiterStoreConfig) (limiter.Store, error) {
	switch config.Type {
	case "memory", "":
		return memory.NewStore(), nil

	case "redis":
		if config.RedisAddress == "" {
			return nil, fmt.Errorf("redis_address is required when using redis storage")
		}

		redisClient := redis.NewClient(&redis.Options{
			Addr:     config.RedisAddress,
			Password: config.RedisPassword,
			DB:       config.RedisDB,
		})

		if err := redisClient.Ping(ctx).Err(); err != nil {
			return nil, fmt.Errorf("failed to connect to redis at %s: %w", config.RedisAddress, err)
		}

		keyPrefix := config.KeyPrefix
		if keyPrefix == "" {
			keyPrefix = "ratelimit"
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
		return nil, fmt.Errorf("unsupported storage type: %s (supported: memory, redis)", config.Type)
	}
}
