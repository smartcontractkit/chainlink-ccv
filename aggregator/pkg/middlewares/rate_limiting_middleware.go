package middlewares

import (
	"context"
	"fmt"
	"time"

	"github.com/ulule/limiter/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type RateLimitingMiddleware struct {
	store     limiter.Store
	config    model.RateLimitingConfig
	apiConfig model.APIKeyConfig
	enabled   bool
	lggr      logger.SugaredLogger
}

// NewRateLimitingMiddleware creates a new rate limiting middleware with the given store and configuration.
func NewRateLimitingMiddleware(store limiter.Store, config model.RateLimitingConfig, apiConfig model.APIKeyConfig, lggr logger.SugaredLogger) *RateLimitingMiddleware {
	if store == nil {
		return &RateLimitingMiddleware{enabled: false}
	}

	return &RateLimitingMiddleware{
		store:     store,
		config:    config,
		apiConfig: apiConfig,
		enabled:   true,
		lggr:      lggr,
	}
}

func (m *RateLimitingMiddleware) buildKey(callerID, method string) string {
	return fmt.Sprintf("%s:%s", callerID, method)
}

func (m *RateLimitingMiddleware) getLimitConfig(callerID, method string) (model.RateLimitConfig, bool) {
	// Get the API client configuration for the caller
	var apiClient *model.APIClient
	for _, client := range m.apiConfig.Clients {
		if client.ClientID == callerID {
			apiClient = client
			break
		}
	}

	// Use the new GetEffectiveLimit method to resolve the rate limit
	effectiveLimit := m.config.GetEffectiveLimit(callerID, method, apiClient)
	if effectiveLimit != nil {
		return *effectiveLimit, true
	}

	return model.RateLimitConfig{}, false
}

// Intercept implements the gRPC unary server interceptor for rate limiting.
func (m *RateLimitingMiddleware) Intercept(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	if !m.enabled {
		return handler(ctx, req)
	}

	identity, ok := auth.IdentityFromContext(ctx)
	if !ok {
		return handler(ctx, req)
	}

	limitConfig, hasLimit := m.getLimitConfig(identity.CallerID, info.FullMethod)
	if !hasLimit {
		return handler(ctx, req)
	}

	rate := limiter.Rate{
		Period: time.Minute,
		Limit:  int64(limitConfig.LimitPerMinute),
	}

	key := m.buildKey(identity.CallerID, info.FullMethod)

	limiterCtx, err := limiter.New(m.store, rate).Get(ctx, key)
	if err != nil {
		return handler(ctx, req)
	}

	header := metadata.Pairs(
		"X-RateLimit-Limit", fmt.Sprintf("%d", limiterCtx.Limit),
		"X-RateLimit-Remaining", fmt.Sprintf("%d", limiterCtx.Remaining),
		"X-RateLimit-Reset", fmt.Sprintf("%d", limiterCtx.Reset),
	)
	if err := grpc.SendHeader(ctx, header); err != nil {
		m.lggr.Errorf("Failed to send rate limit headers: %v", err)
	}

	if limiterCtx.Reached {
		m.lggr.Warnf("Rate limit exceeded for caller %s on method %s", identity.CallerID, info.FullMethod)
		return nil, status.Errorf(
			codes.ResourceExhausted,
			"rate limit exceeded: %d requests per minute (resets at %v) for caller: %s, method: %s",
			limiterCtx.Limit,
			time.Unix(limiterCtx.Reset, 0).Format(time.RFC3339),
			identity.CallerID,
			info.FullMethod,
		)
	}

	return handler(ctx, req)
}
