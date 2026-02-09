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
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/rate_limiting"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var (
	_                  protocol.HealthReporter = (*RateLimitingMiddleware)(nil)
	globalAnonymousKey                         = "__GLOBAL_ANONYMOUS_KEY__"
	// We are not using ResourceExhausted as this is a shared limit between all anonynous caller.
	ErrGlobalAnonynousLimitReached = status.Error(codes.Unavailable, "service temporarily unavailable")
)

type RateLimitingMiddleware struct {
	store          limiter.Store
	config         model.RateLimitingConfig
	clientProvider auth.ClientProvider
	enabled        bool
	lggr           logger.SugaredLogger
}

// NewRateLimitingMiddleware creates a new rate limiting middleware with the given store and configuration.
func NewRateLimitingMiddleware(store limiter.Store, config model.RateLimitingConfig, clientProvider auth.ClientProvider, lggr logger.SugaredLogger) *RateLimitingMiddleware {
	if store == nil {
		return &RateLimitingMiddleware{enabled: false}
	}

	return &RateLimitingMiddleware{
		store:          store,
		config:         config,
		clientProvider: clientProvider,
		enabled:        true,
		lggr:           lggr,
	}
}

func (m *RateLimitingMiddleware) buildKey(callerID, method string) string {
	return fmt.Sprintf("%s:%s", callerID, method)
}

func (m *RateLimitingMiddleware) getLimitConfig(callerID, method string) (model.RateLimitConfig, bool) {
	// Get the API client configuration for the caller
	apiClient, _ := m.clientProvider.GetClientByClientID(callerID)

	// Use the new GetEffectiveLimit method to resolve the rate limit
	effectiveLimit := m.config.GetEffectiveLimit(callerID, method, apiClient)
	if effectiveLimit != nil {
		return *effectiveLimit, true
	}

	return model.RateLimitConfig{}, false
}

func (m *RateLimitingMiddleware) handleGlobalLimitAnonymous(ctx context.Context, fullMethod string) error {
	if limitConfig, ok := m.config.GlobalAnonymousLimits[fullMethod]; ok {
		globalKey := m.buildKey(globalAnonymousKey, fullMethod)
		rate := limiter.Rate{
			Period: time.Minute,
			Limit:  int64(limitConfig.LimitPerMinute),
		}
		limiterCtx, err := limiter.New(m.store, rate).Get(ctx, globalKey)
		if err != nil {
			m.lggr.Errorw("Rate limiter store error - allowing request (fail-open). Health check will fail.",
				"error", err,
				"callerID", globalAnonymousKey,
				"method", fullMethod)
		}

		if limiterCtx.Reached {
			return ErrGlobalAnonynousLimitReached
		}

		return nil
	}
	return ErrGlobalAnonynousLimitReached
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

	if identity.IsAnonymous {
		if err := m.handleGlobalLimitAnonymous(ctx, info.FullMethod); err != nil {
			return nil, err
		}
	}

	limitConfig, hasLimit := m.getLimitConfig(identity.CallerID, info.FullMethod)
	if !hasLimit {
		limitConfig = model.RateLimitConfig{LimitPerMinute: 0}
	}

	rate := limiter.Rate{
		Period: time.Minute,
		Limit:  int64(limitConfig.LimitPerMinute),
	}

	key := m.buildKey(identity.CallerID, info.FullMethod)

	limiterCtx, err := limiter.New(m.store, rate).Get(ctx, key)
	if err != nil {
		m.lggr.Errorw("Rate limiter store error - allowing request (fail-open). Health check will fail.",
			"error", err,
			"callerID", identity.CallerID,
			"method", info.FullMethod)
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

// NewRateLimitingMiddlewareFromConfig creates a rate limiting middleware from configuration.
func NewRateLimitingMiddlewareFromConfig(config model.RateLimitingConfig, clientProvider auth.ClientProvider, lggr logger.SugaredLogger) (*RateLimitingMiddleware, error) {
	if !config.Enabled {
		return &RateLimitingMiddleware{enabled: false}, nil
	}

	// Check if any limits are configured (caller-specific, group, or default)
	hasLimits := len(config.Limits) > 0 || len(config.GroupLimits) > 0 || len(config.DefaultLimits) > 0
	if !hasLimits {
		return nil, fmt.Errorf("rate limiting is enabled but no limits are configured")
	}

	// Create the storage backend
	store, err := rate_limiting.NewRateLimiterStore(config.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limiter storage: %w", err)
	}

	return NewRateLimitingMiddleware(store, config, clientProvider, lggr), nil
}

func (m *RateLimitingMiddleware) Ready() error {
	if !m.enabled || m.store == nil {
		// rate limiting disabled"
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rate := limiter.Rate{
		Period: time.Minute,
		Limit:  1,
	}

	_, err := m.store.Peek(ctx, "health_check", rate)
	if err != nil {
		return fmt.Errorf("rate limiter store unavailable: %v", err)
	}

	return nil
}

func (m *RateLimitingMiddleware) HealthReport() map[string]error {
	return map[string]error{
		m.Name(): m.Ready(),
	}
}

func (m *RateLimitingMiddleware) Name() string {
	return "rate_limiter"
}
