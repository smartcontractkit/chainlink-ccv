package middlewares

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
)

func RequireAuthInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	_, ok := auth.IdentityFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated: no caller identity in context")
	}
	return handler(ctx, req)
}
