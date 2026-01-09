package middlewares

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func mockServerInfo(fullMethod string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{
		FullMethod: fullMethod,
	}
}

func mockHandler(ctx context.Context, req any) (any, error) {
	return "success", nil
}

func TestRateLimitingMiddleware_Disabled(t *testing.T) {
	middleware := &RateLimitingMiddleware{enabled: false}
	ctx := context.Background()
	info := mockServerInfo("/test.Service/Method")

	resp, err := middleware.Intercept(ctx, nil, info, mockHandler)
	require.NoError(t, err)
	require.Equal(t, "success", resp)
}

func TestRateLimitingMiddleware_DefaultLimits(t *testing.T) {
	store := memory.NewStore()
	config := model.RateLimitingConfig{
		Enabled: true,
		DefaultLimits: map[string]model.RateLimitConfig{
			"/test.Service/Method": {LimitPerMinute: 5},
		},
	}

	client := &mockClientConfig{
		clientID: "test-caller",
		groups:   nil,
		enabled:  true,
	}
	clientProvider := &mockClientProvider{
		clientsByAPIKey: map[string]*mockClientEntry{},
		clientsByID: map[string]auth.ClientConfig{
			"test-caller": client,
		},
	}

	middleware := NewRateLimitingMiddleware(store, config, clientProvider, logger.TestSugared(t))
	identity := auth.CreateCallerIdentity("test-caller", false)
	ctx := auth.ToContext(context.Background(), identity)
	info := mockServerInfo("/test.Service/Method")

	// First 5 requests should succeed
	for i := range 5 {
		resp, err := middleware.Intercept(ctx, nil, info, mockHandler)
		require.NoError(t, err, "request %d should succeed", i+1)
		require.Equal(t, "success", resp)
	}

	// 6th request should be rate limited
	resp, err := middleware.Intercept(ctx, nil, info, mockHandler)
	require.Error(t, err)
	require.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.ResourceExhausted, st.Code())
	require.Contains(t, st.Message(), "rate limit exceeded")
}

func TestRateLimitingMiddleware_GroupLimits(t *testing.T) {
	store := memory.NewStore()
	config := model.RateLimitingConfig{
		Enabled: true,
		GroupLimits: map[string]map[string]model.RateLimitConfig{
			"verifiers": {
				"/test.Service/Method": {LimitPerMinute: 3},
			},
		},
		DefaultLimits: map[string]model.RateLimitConfig{
			"/test.Service/Method": {LimitPerMinute: 10},
		},
	}

	client := &mockClientConfig{
		clientID: "test-caller",
		groups:   []string{"verifiers"},
		enabled:  true,
	}
	clientProvider := &mockClientProvider{
		clientsByAPIKey: map[string]*mockClientEntry{},
		clientsByID: map[string]auth.ClientConfig{
			"test-caller": client,
		},
	}

	middleware := NewRateLimitingMiddleware(store, config, clientProvider, logger.TestSugared(t))
	identity := auth.CreateCallerIdentity("test-caller", false)
	ctx := auth.ToContext(context.Background(), identity)
	info := mockServerInfo("/test.Service/Method")

	// First 3 requests should succeed (group limit)
	for i := range 3 {
		resp, err := middleware.Intercept(ctx, nil, info, mockHandler)
		require.NoError(t, err, "request %d should succeed", i+1)
		require.Equal(t, "success", resp)
	}

	// 4th request should be rate limited (group limit kicks in before default)
	resp, err := middleware.Intercept(ctx, nil, info, mockHandler)
	require.Error(t, err)
	require.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.ResourceExhausted, st.Code())
	require.Contains(t, st.Message(), "rate limit exceeded")
}

func TestRateLimitingMiddleware_MostRestrictiveGroup(t *testing.T) {
	store := memory.NewStore()
	config := model.RateLimitingConfig{
		Enabled: true,
		GroupLimits: map[string]map[string]model.RateLimitConfig{
			"group1": {
				"/test.Service/Method": {LimitPerMinute: 5},
			},
			"group2": {
				"/test.Service/Method": {LimitPerMinute: 2}, // More restrictive
			},
		},
		DefaultLimits: map[string]model.RateLimitConfig{
			"/test.Service/Method": {LimitPerMinute: 10},
		},
	}

	client := &mockClientConfig{
		clientID: "test-caller",
		groups:   []string{"group1", "group2"}, // Multiple groups
		enabled:  true,
	}
	clientProvider := &mockClientProvider{
		clientsByAPIKey: map[string]*mockClientEntry{},
		clientsByID: map[string]auth.ClientConfig{
			"test-caller": client,
		},
	}

	middleware := NewRateLimitingMiddleware(store, config, clientProvider, logger.TestSugared(t))
	identity := auth.CreateCallerIdentity("test-caller", false)
	ctx := auth.ToContext(context.Background(), identity)
	info := mockServerInfo("/test.Service/Method")

	// First 2 requests should succeed (most restrictive group limit)
	for i := range 2 {
		resp, err := middleware.Intercept(ctx, nil, info, mockHandler)
		require.NoError(t, err, "request %d should succeed", i+1)
		require.Equal(t, "success", resp)
	}

	// 3rd request should be rate limited (most restrictive group limit applied)
	resp, err := middleware.Intercept(ctx, nil, info, mockHandler)
	require.Error(t, err)
	require.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.ResourceExhausted, st.Code())
	require.Contains(t, st.Message(), "rate limit exceeded")
}

func TestRateLimitingMiddleware_CallerSpecificOverridesGroup(t *testing.T) {
	store := memory.NewStore()
	config := model.RateLimitingConfig{
		Enabled: true,
		Limits: map[string]map[string]model.RateLimitConfig{
			"test-caller": {
				"/test.Service/Method": {LimitPerMinute: 1}, // Most specific - should override group
			},
		},
		GroupLimits: map[string]map[string]model.RateLimitConfig{
			"verifiers": {
				"/test.Service/Method": {LimitPerMinute: 5},
			},
		},
		DefaultLimits: map[string]model.RateLimitConfig{
			"/test.Service/Method": {LimitPerMinute: 10},
		},
	}

	client := &mockClientConfig{
		clientID: "test-caller",
		groups:   []string{"verifiers"},
		enabled:  true,
	}
	clientProvider := &mockClientProvider{
		clientsByAPIKey: map[string]*mockClientEntry{},
		clientsByID: map[string]auth.ClientConfig{
			"test-caller": client,
		},
	}

	middleware := NewRateLimitingMiddleware(store, config, clientProvider, logger.TestSugared(t))
	identity := auth.CreateCallerIdentity("test-caller", false)
	ctx := auth.ToContext(context.Background(), identity)
	info := mockServerInfo("/test.Service/Method")

	// First request should succeed
	resp, err := middleware.Intercept(ctx, nil, info, mockHandler)
	require.NoError(t, err)
	require.Equal(t, "success", resp)

	// 2nd request should be rate limited (caller-specific limit overrides group)
	resp, err = middleware.Intercept(ctx, nil, info, mockHandler)
	require.Error(t, err)
	require.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.ResourceExhausted, st.Code())
	require.Contains(t, st.Message(), "rate limit exceeded")
}
