package middlewares

import (
	"context"

	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
)

type ScopingMiddleware struct{}

func (m *ScopingMiddleware) Intercept(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	ctx = scope.WithRequestID(ctx)
	ctx = scope.WithAPIName(ctx, info.FullMethod)
	return handler(ctx, req)
}

func NewScopingMiddleware() *ScopingMiddleware {
	return &ScopingMiddleware{}
}
