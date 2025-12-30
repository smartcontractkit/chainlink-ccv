package middlewares

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/smartcontractkit/chainlink-ccv/common/auth"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestNewAnonymousAuthMiddleware_ParsesTrustedProxies(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		expectError    bool
		errorContains  string
	}{
		{
			name:           "empty list creates middleware with no trusted proxies",
			trustedProxies: []string{},
			expectError:    false,
		},
		{
			name:           "nil list creates middleware with no trusted proxies",
			trustedProxies: nil,
			expectError:    false,
		},
		{
			name:           "valid CIDR ranges are parsed successfully",
			trustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			expectError:    false,
		},
		{
			name:           "valid single IPv4 is converted to /32 CIDR",
			trustedProxies: []string{"192.168.1.1"},
			expectError:    false,
		},
		{
			name:           "valid single IPv6 is converted to /128 CIDR",
			trustedProxies: []string{"::1"},
			expectError:    false,
		},
		{
			name:           "invalid CIDR returns error",
			trustedProxies: []string{"invalid-cidr"},
			expectError:    true,
			errorContains:  "invalid trusted proxy",
		},
		{
			name:           "invalid IP returns error",
			trustedProxies: []string{"999.999.999.999"},
			expectError:    true,
			errorContains:  "invalid trusted proxy",
		},
		{
			name:           "mixed valid and invalid returns error",
			trustedProxies: []string{"10.0.0.0/8", "not-valid"},
			expectError:    true,
			errorContains:  "invalid trusted proxy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := NewAnonymousAuthMiddleware(tt.trustedProxies, logger.Test(t))

			if tt.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorContains)
				require.Nil(t, middleware)
			} else {
				require.NoError(t, err)
				require.NotNil(t, middleware)
			}
		})
	}
}

func TestAnonymousAuthMiddleware_IsTrustedProxy(t *testing.T) {
	middleware, err := NewAnonymousAuthMiddleware([]string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.1.100",
	}, logger.Test(t))
	require.NoError(t, err)

	tests := []struct {
		name      string
		ipStr     string
		isTrusted bool
	}{
		{
			name:      "IP in 10.0.0.0/8 range is trusted",
			ipStr:     "10.1.2.3",
			isTrusted: true,
		},
		{
			name:      "IP with port in 10.0.0.0/8 range is trusted",
			ipStr:     "10.1.2.3:50051",
			isTrusted: true,
		},
		{
			name:      "IP in 172.16.0.0/12 range is trusted",
			ipStr:     "172.17.0.1",
			isTrusted: true,
		},
		{
			name:      "specific IP 192.168.1.100 is trusted",
			ipStr:     "192.168.1.100",
			isTrusted: true,
		},
		{
			name:      "specific IP 192.168.1.100 with port is trusted",
			ipStr:     "192.168.1.100:8080",
			isTrusted: true,
		},
		{
			name:      "IP outside trusted ranges is not trusted",
			ipStr:     "8.8.8.8",
			isTrusted: false,
		},
		{
			name:      "IP 192.168.1.101 (not exact match) is not trusted",
			ipStr:     "192.168.1.101",
			isTrusted: false,
		},
		{
			name:      "invalid IP string is not trusted",
			ipStr:     "not-an-ip",
			isTrusted: false,
		},
		{
			name:      "empty string is not trusted",
			ipStr:     "",
			isTrusted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := middleware.isTrustedProxy(tt.ipStr)
			require.Equal(t, tt.isTrusted, result)
		})
	}
}

func TestAnonymousAuthMiddleware_IsTrustedProxy_IPv6(t *testing.T) {
	middleware, err := NewAnonymousAuthMiddleware([]string{
		"2001:db8::/32",
		"fd00::/8",
		"::1",
	}, logger.Test(t))
	require.NoError(t, err)

	tests := []struct {
		name      string
		ipStr     string
		isTrusted bool
	}{
		{
			name:      "IPv6 in 2001:db8::/32 range is trusted",
			ipStr:     "2001:db8::1",
			isTrusted: true,
		},
		{
			name:      "IPv6 with port in 2001:db8::/32 range is trusted",
			ipStr:     "[2001:db8::1]:50051",
			isTrusted: true,
		},
		{
			name:      "IPv6 in fd00::/8 (unique local) range is trusted",
			ipStr:     "fd12:3456:789a::1",
			isTrusted: true,
		},
		{
			name:      "IPv6 localhost ::1 is trusted",
			ipStr:     "::1",
			isTrusted: true,
		},
		{
			name:      "IPv6 localhost with port is trusted",
			ipStr:     "[::1]:8080",
			isTrusted: true,
		},
		{
			name:      "IPv6 outside trusted ranges is not trusted",
			ipStr:     "2607:f8b0:4004:800::200e",
			isTrusted: false,
		},
		{
			name:      "IPv6 outside fd00::/8 is not trusted",
			ipStr:     "fe80::1",
			isTrusted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := middleware.isTrustedProxy(tt.ipStr)
			require.Equal(t, tt.isTrusted, result)
		})
	}
}

func TestAnonymousAuthMiddleware_TryGetIP_WithNoTrustedProxies_UsesPeerIP(t *testing.T) {
	middleware, err := NewAnonymousAuthMiddleware([]string{}, logger.Test(t))
	require.NoError(t, err)

	tests := []struct {
		name         string
		setupContext func() context.Context
		expectedIP   string
		expectFound  bool
	}{
		{
			name: "ignores X-Forwarded-For header and uses peer IP when no trusted proxies",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
					"x-forwarded-for": "1.2.3.4",
				}))
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051},
				})
				return ctx
			},
			expectedIP:  "10.0.0.1",
			expectFound: true,
		},
		{
			name: "uses peer IP directly when no trusted proxies configured",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051},
				})
				return ctx
			},
			expectedIP:  "10.0.0.1",
			expectFound: true,
		},
		{
			name: "returns false when no peer in context",
			setupContext: func() context.Context {
				return context.Background()
			},
			expectedIP:  "",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupContext()
			ip, found := middleware.tryGetIP(ctx)
			require.Equal(t, tt.expectFound, found)
			if tt.expectFound {
				require.Equal(t, tt.expectedIP, ip)
			}
		})
	}
}

func TestAnonymousAuthMiddleware_TryGetIP_WithTrustedProxies(t *testing.T) {
	middleware, err := NewAnonymousAuthMiddleware([]string{"10.0.0.0/8"}, logger.Test(t))
	require.NoError(t, err)

	tests := []struct {
		name         string
		setupContext func() context.Context
		expectedIP   string
		expectFound  bool
	}{
		{
			name: "trusts X-Forwarded-For when peer is trusted proxy",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
					"x-forwarded-for": "203.0.113.50",
				}))
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051},
				})
				return ctx
			},
			expectedIP:  "203.0.113.50",
			expectFound: true,
		},
		{
			name: "trusts X-Real-IP when peer is trusted proxy and no X-Forwarded-For",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
					"x-real-ip": "203.0.113.51",
				}))
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051},
				})
				return ctx
			},
			expectedIP:  "203.0.113.51",
			expectFound: true,
		},
		{
			name: "prefers X-Forwarded-For over X-Real-IP when peer is trusted",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
					"x-forwarded-for": "203.0.113.50",
					"x-real-ip":       "203.0.113.51",
				}))
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051},
				})
				return ctx
			},
			expectedIP:  "203.0.113.50",
			expectFound: true,
		},
		{
			name: "uses peer IP when peer is NOT trusted proxy (ignores spoofed X-Forwarded-For)",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
					"x-forwarded-for": "1.2.3.4",
				}))
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 50051},
				})
				return ctx
			},
			expectedIP:  "8.8.8.8",
			expectFound: true,
		},
		{
			name: "uses peer IP when peer is NOT trusted (ignores spoofed X-Real-IP)",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
					"x-real-ip": "1.2.3.4",
				}))
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 50051},
				})
				return ctx
			},
			expectedIP:  "8.8.8.8",
			expectFound: true,
		},
		{
			name: "uses peer IP (without port) when trusted proxy but no forwarded headers",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051},
				})
				return ctx
			},
			expectedIP:  "10.0.0.1",
			expectFound: true,
		},
		{
			name: "extracts rightmost IP from comma-separated X-Forwarded-For (prevents spoofing)",
			setupContext: func() context.Context {
				ctx := context.Background()
				// Attacker sends "spoofed-ip" but ALB appends real client IP
				ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
					"x-forwarded-for": "spoofed-ip, another-fake, 203.0.113.99",
				}))
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051},
				})
				return ctx
			},
			expectedIP:  "203.0.113.99",
			expectFound: true,
		},
		{
			name: "handles single IP in X-Forwarded-For",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
					"x-forwarded-for": "203.0.113.50",
				}))
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051},
				})
				return ctx
			},
			expectedIP:  "203.0.113.50",
			expectFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupContext()
			ip, found := middleware.tryGetIP(ctx)
			require.Equal(t, tt.expectFound, found)
			if tt.expectFound {
				require.Equal(t, tt.expectedIP, ip)
			}
		})
	}
}

func TestAnonymousAuthMiddleware_Intercept(t *testing.T) {
	middleware, err := NewAnonymousAuthMiddleware([]string{"10.0.0.0/8"}, logger.Test(t))
	require.NoError(t, err)

	info := &grpc.UnaryServerInfo{FullMethod: "/Test/Method"}

	tests := []struct {
		name             string
		setupContext     func() context.Context
		existingIdentity *auth.CallerIdentity
		expectedCallerID string
		expectIdentity   bool
	}{
		{
			name: "uses peer IP when peer is untrusted (ignores spoofed header)",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
					"x-forwarded-for": "spoofed-ip",
				}))
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 50051},
				})
				return ctx
			},
			expectedCallerID: "8.8.8.8",
			expectIdentity:   true,
		},
		{
			name: "sets identity from X-Forwarded-For when trusted proxy",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
					"x-forwarded-for": "203.0.113.50",
				}))
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051},
				})
				return ctx
			},
			expectedCallerID: "203.0.113.50",
			expectIdentity:   true,
		},
		{
			name: "does not override existing identity",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051},
				})
				return ctx
			},
			existingIdentity: &auth.CallerIdentity{CallerID: "existing-client", IsAnonymous: false},
			expectedCallerID: "existing-client",
			expectIdentity:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupContext()

			if tt.existingIdentity != nil {
				ctx = auth.ToContext(ctx, tt.existingIdentity)
			}

			var capturedCtx context.Context
			handler := func(handlerCtx context.Context, req any) (any, error) {
				capturedCtx = handlerCtx //nolint:fatcontext // Test needs to capture context
				return "response", nil
			}

			resp, err := middleware.Intercept(ctx, "request", info, handler)
			require.NoError(t, err)
			require.Equal(t, "response", resp)

			identity, ok := auth.IdentityFromContext(capturedCtx)
			if tt.expectIdentity {
				require.True(t, ok, "expected identity in context")
				require.Equal(t, tt.expectedCallerID, identity.CallerID)
			} else {
				require.False(t, ok, "expected no identity in context for untrusted peer")
			}
		})
	}
}

func TestAnonymousAuthMiddleware_TryGetIP_IPv6(t *testing.T) {
	middleware, err := NewAnonymousAuthMiddleware([]string{"fd00::/8", "::1"}, logger.Test(t))
	require.NoError(t, err)

	tests := []struct {
		name         string
		setupContext func() context.Context
		expectedIP   string
		expectFound  bool
	}{
		{
			name: "trusts X-Forwarded-For when IPv6 peer is trusted proxy",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
					"x-forwarded-for": "2607:f8b0:4004:800::200e",
				}))
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("fd00::1"), Port: 50051},
				})
				return ctx
			},
			expectedIP:  "2607:f8b0:4004:800::200e",
			expectFound: true,
		},
		{
			name: "uses peer IP when IPv6 peer is NOT trusted (ignores spoofed header)",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
					"x-forwarded-for": "2001:db8::1",
				}))
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("2607:f8b0:4004:800::200e"), Port: 50051},
				})
				return ctx
			},
			expectedIP:  "2607:f8b0:4004:800::200e",
			expectFound: true,
		},
		{
			name: "uses IPv6 peer IP (without port) when trusted proxy but no forwarded headers",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = peer.NewContext(ctx, &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("::1"), Port: 50051},
				})
				return ctx
			},
			expectedIP:  "::1",
			expectFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupContext()
			ip, found := middleware.tryGetIP(ctx)
			require.Equal(t, tt.expectFound, found)
			if tt.expectFound {
				require.Equal(t, tt.expectedIP, ip)
			}
		})
	}
}

func TestAnonymousAuthMiddleware_MixedIPv4AndIPv6(t *testing.T) {
	middleware, err := NewAnonymousAuthMiddleware([]string{
		"10.0.0.0/8",
		"fd00::/8",
	}, logger.Test(t))
	require.NoError(t, err)

	t.Run("IPv4 peer trusted with IPv6 also configured", func(t *testing.T) {
		result := middleware.isTrustedProxy("10.1.2.3:50051")
		require.True(t, result)
	})

	t.Run("IPv6 peer trusted with IPv4 also configured", func(t *testing.T) {
		result := middleware.isTrustedProxy("[fd00::1]:50051")
		require.True(t, result)
	})

	t.Run("untrusted IPv4 rejected in mixed config", func(t *testing.T) {
		result := middleware.isTrustedProxy("8.8.8.8:50051")
		require.False(t, result)
	})

	t.Run("untrusted IPv6 rejected in mixed config", func(t *testing.T) {
		result := middleware.isTrustedProxy("[2607:f8b0::1]:50051")
		require.False(t, result)
	})
}

func TestAnonymousAuthMiddleware_SecurityScenario_IPSpoofingPrevention(t *testing.T) {
	middleware, err := NewAnonymousAuthMiddleware([]string{"10.0.0.0/8"}, logger.Test(t))
	require.NoError(t, err)

	t.Run("attacker from untrusted peer is rate limited by their real IP", func(t *testing.T) {
		// Attacker connects directly (not through ALB) with public IP
		// and tries to set X-Forwarded-For to victim's IP
		attackerPeerIP := "203.0.113.100" // Attacker's real IP (not trusted)
		victimIP := "192.168.1.50"        // IP attacker wants to impersonate

		ctx := context.Background()
		ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
			"x-forwarded-for": victimIP, // Attacker trying to spoof
		}))
		ctx = peer.NewContext(ctx, &peer.Peer{
			Addr: &net.TCPAddr{IP: net.ParseIP(attackerPeerIP), Port: 50051},
		})

		ip, found := middleware.tryGetIP(ctx)
		// Attacker gets their real IP, not the spoofed one
		require.True(t, found)
		require.Equal(t, attackerPeerIP, ip, "untrusted peer should be identified by their real IP, not spoofed header")
	})

	t.Run("legitimate request through ALB uses forwarded IP", func(t *testing.T) {
		// Request comes through ALB (trusted proxy)
		albIP := "10.0.0.50"        // ALB's internal IP (trusted)
		clientIP := "203.0.113.200" // Real client's public IP

		ctx := context.Background()
		ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
			"x-forwarded-for": clientIP, // ALB sets real client IP
		}))
		ctx = peer.NewContext(ctx, &peer.Peer{
			Addr: &net.TCPAddr{IP: net.ParseIP(albIP), Port: 50051},
		})

		ip, found := middleware.tryGetIP(ctx)
		require.True(t, found)
		// Should trust the X-Forwarded-For since peer is trusted ALB
		require.Equal(t, clientIP, ip)
	})
}

func TestAnonymousAuthMiddleware_NoTrustedProxies_UsesPeerIPDirectly(t *testing.T) {
	middleware, err := NewAnonymousAuthMiddleware([]string{}, logger.Test(t))
	require.NoError(t, err)

	info := &grpc.UnaryServerInfo{FullMethod: "/Test/Method"}

	t.Run("identity set with peer IP when no trusted proxies configured", func(t *testing.T) {
		ctx := context.Background()
		ctx = peer.NewContext(ctx, &peer.Peer{
			Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051},
		})

		var capturedCtx context.Context
		handler := func(handlerCtx context.Context, req any) (any, error) {
			capturedCtx = handlerCtx //nolint:fatcontext // Test needs to capture context
			return "response", nil
		}

		resp, err := middleware.Intercept(ctx, "request", info, handler)
		require.NoError(t, err)
		require.Equal(t, "response", resp)

		identity, ok := auth.IdentityFromContext(capturedCtx)
		require.True(t, ok, "identity should be set with peer IP when no trusted proxies configured")
		require.Equal(t, "10.0.0.1", identity.CallerID)
		require.True(t, identity.IsAnonymous)
	})
}
