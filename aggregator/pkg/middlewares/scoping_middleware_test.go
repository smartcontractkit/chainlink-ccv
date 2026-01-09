package middlewares

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
)

func TestScopingMiddleware_Intercept(t *testing.T) {
	middleware := NewScopingMiddleware()

	t.Run("adds request ID to context", func(t *testing.T) {
		var capturedRequestID string
		var requestIDFound bool

		handler := func(ctx context.Context, req any) (any, error) {
			capturedRequestID, requestIDFound = scope.RequestIDFromContext(ctx)
			return testResponse, nil
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/TestService/TestMethod"}

		resp, err := middleware.Intercept(context.Background(), "request", info, handler)

		require.NoError(t, err)
		assert.Equal(t, testResponse, resp)
		require.True(t, requestIDFound, "request ID should be present in context")
		assert.NotEmpty(t, capturedRequestID)
		assert.Len(t, capturedRequestID, 36, "request ID should be a UUID")
	})

	t.Run("adds API name to context", func(t *testing.T) {
		var capturedAPIName string
		var apiNameFound bool

		handler := func(ctx context.Context, req any) (any, error) {
			capturedAPIName, apiNameFound = scope.APINameFromContext(ctx)
			return testResponse, nil
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/TestService/TestMethod"}

		resp, err := middleware.Intercept(context.Background(), "request", info, handler)

		require.NoError(t, err)
		assert.Equal(t, testResponse, resp)
		require.True(t, apiNameFound, "API name should be present in context")
		assert.Equal(t, "/TestService/TestMethod", capturedAPIName)
	})

	t.Run("passes through handler error", func(t *testing.T) {
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

func TestNewScopingMiddleware(t *testing.T) {
	middleware := NewScopingMiddleware()
	assert.NotNil(t, middleware)
}
