package middlewares

import (
	"context"
	"time"

	"google.golang.org/grpc"
)

type RequestTimeoutMiddleware struct {
	timeout time.Duration
}

func NewRequestTimeoutMiddleware(timeout time.Duration) *RequestTimeoutMiddleware {
	return &RequestTimeoutMiddleware{timeout: timeout}
}

func (m *RequestTimeoutMiddleware) Intercept(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if m.timeout <= 0 {
		return handler(ctx, req)
	}

	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	return handler(ctx, req)
}
