package middlewares

import (
	"context"
	"fmt"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type AnonymousAuthMiddleware struct {
	trustedProxies []*net.IPNet
	logger         logger.Logger
}

func NewAnonymousAuthMiddleware(trustedProxyCIDRs []string, lggr logger.Logger) (*AnonymousAuthMiddleware, error) {
	trustedProxies := make([]*net.IPNet, 0, len(trustedProxyCIDRs))
	for _, cidr := range trustedProxyCIDRs {
		ipNet, err := parseCIDROrIP(cidr)
		if err != nil {
			return nil, err
		}
		trustedProxies = append(trustedProxies, ipNet)
	}
	return &AnonymousAuthMiddleware{trustedProxies: trustedProxies, logger: lggr}, nil
}

func parseCIDROrIP(s string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err == nil {
		return ipNet, nil
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid trusted proxy '%s': not a valid CIDR or IP", s)
	}

	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

func (m *AnonymousAuthMiddleware) Intercept(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	_, ok := auth.IdentityFromContext(ctx)
	if ok {
		// Identity already present, pass through
		return handler(ctx, req)
	}

	if ip, ok := m.tryGetIP(ctx); ok {
		ctx = auth.ToContext(ctx, auth.CreateCallerIdentity(ip, true))
	}

	return handler(ctx, req)
}

func (m *AnonymousAuthMiddleware) isTrustedProxy(ipStr string) bool {
	// Extract IP from "ip:port" format
	host, _, err := net.SplitHostPort(ipStr)
	if err != nil {
		host = ipStr // No port, use as-is
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Normalize IPv4 to 4-byte format for consistent comparison.
	// net.ParseIP returns a 16-byte representation, but parseCIDROrIP
	// stores IPv4 trusted proxies as 4-byte IPNets. Both must use the
	// same format for IPNet.Contains to match correctly.
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	for _, trusted := range m.trustedProxies {
		if trusted.Contains(ip) {
			return true
		}
	}
	return false
}

func (m *AnonymousAuthMiddleware) tryGetIP(ctx context.Context) (string, bool) {
	// If no trusted proxies are configured, anonymous auth is disabled
	if len(m.trustedProxies) == 0 {
		return "", false
	}

	peerIP, hasPeer := ipFromPeer(ctx)
	if !hasPeer {
		m.logger.Infow("Anonymous auth rejected: no peer IP in context")
		return "", false
	}

	// Only allow anonymous auth if peer is a trusted proxy
	if !m.isTrustedProxy(peerIP) {
		m.logger.Infow("Anonymous auth rejected: peer is not a trusted proxy", "peerIP", peerIP)
		return "", false
	}

	if ip, ok := ipFromForwardedFor(ctx); ok {
		return ip, true
	}
	if ip, ok := ipFromRealIP(ctx); ok {
		return ip, true
	}

	// Trusted proxy but no forwarded headers - use proxy IP
	return peerIP, true
}

func ipFromForwardedFor(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}

	values := md.Get("x-forwarded-for")
	if len(values) == 0 {
		return "", false
	}

	// X-Forwarded-For can be comma-separated: "client, proxy1, proxy2"
	// The rightmost IP is the one added by the trusted proxy (ALB),
	// representing the actual client IP that connected to the proxy.
	// Left entries may be spoofed by the client.
	// See https://docs.aws.amazon.com/elasticloadbalancing/latest/application/x-forwarded-headers.html#x-forwarded-for
	parts := strings.Split(values[0], ",")
	rightmost := strings.TrimSpace(parts[len(parts)-1])
	if rightmost == "" {
		return "", false
	}

	return rightmost, true
}

func ipFromRealIP(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}

	ip := md.Get("x-real-ip")

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
