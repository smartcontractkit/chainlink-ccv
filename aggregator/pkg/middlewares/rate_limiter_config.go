package middlewares

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// NewRateLimitingMiddlewareFromConfig creates a rate limiting middleware from configuration.
func NewRateLimitingMiddlewareFromConfig(config model.RateLimitingConfig, apiConfig model.APIKeyConfig, lggr logger.SugaredLogger) (*RateLimitingMiddleware, error) {
	if !config.Enabled {
		return &RateLimitingMiddleware{enabled: false}, nil
	}

	// Check if any limits are configured (caller-specific, group, or default)
	hasLimits := len(config.Limits) > 0 || len(config.GroupLimits) > 0 || len(config.DefaultLimits) > 0
	if !hasLimits {
		return nil, fmt.Errorf("rate limiting is enabled but no limits are configured")
	}

	// Create the storage backend
	store, err := NewRateLimiterStore(config.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limiter storage: %w", err)
	}

	return NewRateLimitingMiddleware(store, config, apiConfig, lggr), nil
}
