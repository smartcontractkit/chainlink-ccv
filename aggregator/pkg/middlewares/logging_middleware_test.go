package middlewares

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestLoggingMiddleware_Intercept(t *testing.T) {
	lggr := logger.Sugared(logger.Test(t))
	middleware := NewLoggingMiddleware(lggr)

	t.Run("passes through successful response", func(t *testing.T) {
		handler := func(ctx context.Context, req any) (any, error) {
			return testResponse, nil
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/TestService/TestMethod"}

		resp, err := middleware.Intercept(context.Background(), "request", info, handler)

		require.NoError(t, err)
		assert.Equal(t, testResponse, resp)
	})

	t.Run("passes through error response", func(t *testing.T) {
		expectedErr := assert.AnError
		handler := func(ctx context.Context, req any) (any, error) {
			return nil, expectedErr
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/TestService/TestMethod"}

		resp, err := middleware.Intercept(context.Background(), "request", info, handler)

		require.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.Nil(t, resp)
	})

	t.Run("passes request to handler", func(t *testing.T) {
		var capturedReq any
		handler := func(ctx context.Context, req any) (any, error) {
			capturedReq = req
			return testResponse, nil
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/TestService/TestMethod"}

		_, err := middleware.Intercept(context.Background(), "test-request", info, handler)

		require.NoError(t, err)
		assert.Equal(t, "test-request", capturedReq)
	})
}

func TestNewLoggingMiddleware(t *testing.T) {
	lggr := logger.Sugared(logger.Test(t))
	middleware := NewLoggingMiddleware(lggr)
	assert.NotNil(t, middleware)
}
