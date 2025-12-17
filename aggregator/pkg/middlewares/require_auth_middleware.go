package middlewares

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type RequireAuthMiddleware struct {
	l logger.SugaredLogger
}

func NewRequireAuthMiddleware(l logger.SugaredLogger) *RequireAuthMiddleware {
	return &RequireAuthMiddleware{l: l}
}

func (m *RequireAuthMiddleware) Intercept(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	_, ok := auth.IdentityFromContext(ctx)
	if !ok {
		reqLogger := scope.AugmentLogger(ctx, m.l)
		reqLogger.Warn("Authentication failed: no caller identity in context")
		return nil, status.Error(codes.Unauthenticated, "unauthenticated: no caller identity in context")
	}
	return handler(ctx, req)
}
