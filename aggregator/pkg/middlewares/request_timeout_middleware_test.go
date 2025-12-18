package middlewares

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

const testResponse = "response"

func TestRequestTimeoutMiddleware_AppliesTimeout(t *testing.T) {
	middleware := NewRequestTimeoutMiddleware(100 * time.Millisecond)

	handlerCalled := false
	ctxChan := make(chan context.Context, 1)

	handler := func(ctx context.Context, _ any) (any, error) {
		handlerCalled = true
		ctxChan <- ctx
		return testResponse, nil
	}

	ctx := context.Background()
	resp, err := middleware.Intercept(ctx, "request", &grpc.UnaryServerInfo{}, handler)

	require.NoError(t, err)
	assert.Equal(t, testResponse, resp)
	assert.True(t, handlerCalled)

	receivedCtx := <-ctxChan
	deadline, ok := receivedCtx.Deadline()
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(100*time.Millisecond), deadline, 50*time.Millisecond)
}

func TestRequestTimeoutMiddleware_CancelsContextOnTimeout(t *testing.T) {
	middleware := NewRequestTimeoutMiddleware(10 * time.Millisecond)

	handler := func(ctx context.Context, _ any) (any, error) {
		select {
		case <-time.After(100 * time.Millisecond):
			return "should not reach", nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	ctx := context.Background()
	_, err := middleware.Intercept(ctx, "request", &grpc.UnaryServerInfo{}, handler)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}
