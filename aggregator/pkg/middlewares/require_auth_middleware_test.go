package middlewares

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestRequireAuthMiddleware_Intercept(t *testing.T) {
	lggr := logger.Sugared(logger.Test(t))
	middleware := NewRequireAuthMiddleware(lggr)

	t.Run("allows request when identity is present", func(t *testing.T) {
		identity := auth.CreateCallerIdentity("test-client", false)
		ctx := auth.ToContext(context.Background(), identity)

		handler := func(ctx context.Context, req any) (any, error) {
			return testResponse, nil
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/TestService/TestMethod"}

		resp, err := middleware.Intercept(ctx, "request", info, handler)

		require.NoError(t, err)
		assert.Equal(t, testResponse, resp)
	})

	t.Run("rejects request when identity is missing", func(t *testing.T) {
		handler := func(ctx context.Context, req any) (any, error) {
			return testResponse, nil
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/TestService/TestMethod"}

		resp, err := middleware.Intercept(context.Background(), "request", info, handler)

		require.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "no caller identity in context")
	})

	t.Run("passes through handler error when identity is present", func(t *testing.T) {
		identity := auth.CreateCallerIdentity("test-client", false)
		ctx := auth.ToContext(context.Background(), identity)

		expectedErr := assert.AnError
		handler := func(ctx context.Context, req any) (any, error) {
			return nil, expectedErr
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/TestService/TestMethod"}

		resp, err := middleware.Intercept(ctx, "request", info, handler)

		require.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.Nil(t, resp)
	})
}

func TestNewRequireAuthMiddleware(t *testing.T) {
	lggr := logger.Sugared(logger.Test(t))
	middleware := NewRequireAuthMiddleware(lggr)
	assert.NotNil(t, middleware)
}
