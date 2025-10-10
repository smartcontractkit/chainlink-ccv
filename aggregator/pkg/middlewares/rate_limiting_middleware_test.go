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

// mockServerInfo returns a pointer to grpc.UnaryServerInfo for testing.
func mockServerInfo(fullMethod string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{
		FullMethod: fullMethod,
	}
}

// mockHandler is a simple handler that returns success.
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
	limits := map[string]map[string]model.RateLimitConfig{
		"default": {
			"/test.Service/Method": {LimitPerMinute: 5},
		},
	}

	middleware := NewRateLimitingMiddleware(store, limits, logger.TestSugared(t))
	identity := auth.CreateCallerIdentity("test-caller", false)
	ctx := auth.ToContext(context.Background(), identity)
	info := mockServerInfo("/test.Service/Method")

	// First 5 requests should succeed
	for i := 0; i < 5; i++ {
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
