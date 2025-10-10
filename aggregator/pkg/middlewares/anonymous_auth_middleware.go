package middlewares

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
)

type AnonymousAuthMiddleware struct{}

func NewAnonymousAuthMiddleware() *AnonymousAuthMiddleware {
	return &AnonymousAuthMiddleware{}
}

func (m *AnonymousAuthMiddleware) Intercept(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	_, ok := auth.IdentityFromContext(ctx)
	if ok {
		// Identity already present, pass through
		return handler(ctx, req)
	}

	if ip, ok := tryGetIP(ctx); ok {
		ctx = auth.ToContext(ctx, auth.CreateCallerIdentity(ip, true))
	}

	return handler(ctx, req)
}

func tryGetIP(ctx context.Context) (string, bool) {
	if ip, ok := ipFromForwardedFor(ctx); ok {
		return ip, true
	}
	if ip, ok := ipFromRealIP(ctx); ok {
		return ip, true
	}
	if ip, ok := ipFromPeer(ctx); ok {
		return ip, true
	}
	return "", false
}

func ipFromForwardedFor(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}

	ip := md.Get("X-Forwarded-For")

	if len(ip) == 0 {
		return "", false
	}

	return ip[0], true
}

func ipFromRealIP(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}

	ip := md.Get("X-Real-IP")

	if len(ip) == 0 {
		return "", false
	}

	return ip[0], true
}

func ipFromPeer(ctx context.Context) (string, bool) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return "", false
	}

	if peer.Addr == nil {
		return "", false
	}

	return peer.Addr.String(), true
}
