package middlewares

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// NewRateLimitingMiddlewareFromConfig creates a rate limiting middleware from configuration.
func NewRateLimitingMiddlewareFromConfig(ctx context.Context, config model.RateLimitingConfig, lggr logger.SugaredLogger) (*RateLimitingMiddleware, error) {
	if !config.Enabled {
		return &RateLimitingMiddleware{enabled: false}, nil
	}

	if len(config.Limits) == 0 {
		return nil, fmt.Errorf("rate limiting is enabled but no limits are configured")
	}

	// Create the storage backend
	store, err := NewRateLimiterStore(ctx, config.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limiter storage: %w", err)
	}

	return NewRateLimitingMiddleware(store, config.Limits, lggr), nil
}
