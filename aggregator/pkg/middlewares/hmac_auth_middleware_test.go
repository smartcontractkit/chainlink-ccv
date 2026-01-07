package middlewares

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

const (
	testAPIKey1        = "00000000-0000-0000-0000-000000000001"
	testSecretCurrent1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

type mockAPIKeyPair struct {
	apiKey string
	secret string
}

func (m *mockAPIKeyPair) GetAPIKey() string { return m.apiKey }
func (m *mockAPIKeyPair) GetSecret() string { return m.secret }

type mockClientConfig struct {
	clientID string
	groups   []string
	enabled  bool
}

func (m *mockClientConfig) GetClientID() string { return m.clientID }
func (m *mockClientConfig) GetGroups() []string { return m.groups }
func (m *mockClientConfig) IsEnabled() bool     { return m.enabled }

type mockClientProvider struct {
	clientsByAPIKey map[string]*mockClientEntry
	clientsByID     map[string]auth.ClientConfig
}

type mockClientEntry struct {
	config auth.ClientConfig
	pair   auth.APIKeyPair
}

func (m *mockClientProvider) GetClientByAPIKey(apiKey string) (auth.ClientConfig, auth.APIKeyPair, bool) {
	if entry, ok := m.clientsByAPIKey[apiKey]; ok {
		return entry.config, entry.pair, true
	}
	return nil, nil, false
}

func (m *mockClientProvider) GetClientByClientID(clientID string) (auth.ClientConfig, bool) {
	if config, ok := m.clientsByID[clientID]; ok {
		return config, true
	}
	return nil, false
}

func generateTestSignature(
	t *testing.T,
	secret, method string,
	req proto.Message,
	apiKey string,
	timestampMs int64,
) string {
	signature, err := hmacutil.GenerateSignature(secret, method, req, apiKey, timestampMs)
	require.NoError(t, err, "Failed to generate signature")
	return signature
}

func createTestClientProvider() *mockClientProvider {
	client1 := &mockClientConfig{
		clientID: "client-1",
		groups:   nil,
		enabled:  true,
	}
	client2 := &mockClientConfig{
		clientID: "client-2",
		groups:   nil,
		enabled:  true,
	}

	return &mockClientProvider{
		clientsByAPIKey: map[string]*mockClientEntry{
			testAPIKey1: {
				config: client1,
				pair:   &mockAPIKeyPair{apiKey: testAPIKey1, secret: testSecretCurrent1},
			},
			"00000000-0000-0000-0000-000000000002": {
				config: client2,
				pair:   &mockAPIKeyPair{apiKey: "00000000-0000-0000-0000-000000000002", secret: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"},
			},
		},
		clientsByID: map[string]auth.ClientConfig{
			"client-1": client1,
			"client-2": client2,
		},
	}
}

type contextCapturingHandler struct {
	capturedCtx context.Context //nolint:containedctx // test helper needs to capture context for assertion
}

func (h *contextCapturingHandler) Handle(ctx context.Context, req any) (any, error) {
	h.capturedCtx = ctx //nolint:fatcontext // test helper needs to capture context for assertion
	return &committeepb.ReadChainStatusResponse{Statuses: []*committeepb.ChainStatus{}}, nil
}

func TestHMACAuthMiddleware(t *testing.T) {
	clientProvider := createTestClientProvider()
	lggr := logger.Test(t)
	middleware := NewHMACAuthMiddleware(clientProvider, lggr)

	req := &committeepb.ReadChainStatusRequest{}
	method := "/Aggregator/ReadChainStatus"
	info := &grpc.UnaryServerInfo{FullMethod: method}

	tests := []struct {
		name              string
		setupMetadata     func() metadata.MD
		expectError       bool
		expectedErrorCode codes.Code
		expectedErrorMsg  string
		validateIdentity  bool
		expectedClientID  string
	}{
		{
			name: "valid signature passes authentication and sets caller identity",
			setupMetadata: func() metadata.MD {
				timestampMs := time.Now().UnixMilli()
				apiKey := testAPIKey1
				secret := testSecretCurrent1
				signature := generateTestSignature(t, secret, method, req, apiKey, timestampMs)
				return metadata.New(map[string]string{
					hmacutil.HeaderAuthorization: apiKey,
					hmacutil.HeaderTimestamp:     strconv.FormatInt(timestampMs, 10),
					hmacutil.HeaderSignature:     signature,
				})
			},
			expectError:      false,
			validateIdentity: true,
			expectedClientID: "client-1",
		},
		{
			name: "invalid signature returns Unauthenticated error",
			setupMetadata: func() metadata.MD {
				timestampMs := time.Now().UnixMilli()
				apiKey := testAPIKey1
				return metadata.New(map[string]string{
					hmacutil.HeaderAuthorization: apiKey,
					hmacutil.HeaderTimestamp:     strconv.FormatInt(timestampMs, 10),
					hmacutil.HeaderSignature:     "invalid_signature_here",
				})
			},
			expectError:       true,
			expectedErrorCode: codes.Unauthenticated,
			expectedErrorMsg:  "invalid signature",
			validateIdentity:  false,
		},
		{
			name: "no headers present allows pass-through",
			setupMetadata: func() metadata.MD {
				return metadata.New(map[string]string{})
			},
			expectError:      false,
			validateIdentity: false,
		},
		{
			name: "no metadata allows pass-through",
			setupMetadata: func() metadata.MD {
				return nil
			},
			expectError:      false,
			validateIdentity: false,
		},
		{
			name: "missing authorization header returns Unauthenticated",
			setupMetadata: func() metadata.MD {
				timestampMs := time.Now().UnixMilli()
				return metadata.New(map[string]string{
					hmacutil.HeaderTimestamp: strconv.FormatInt(timestampMs, 10),
					hmacutil.HeaderSignature: "some-signature",
				})
			},
			expectError:       true,
			expectedErrorCode: codes.Unauthenticated,
			expectedErrorMsg:  "missing authorization header",
			validateIdentity:  false,
		},
		{
			name: "missing timestamp header returns Unauthenticated",
			setupMetadata: func() metadata.MD {
				return metadata.New(map[string]string{
					hmacutil.HeaderAuthorization: testAPIKey1,
					hmacutil.HeaderSignature:     "some-signature",
				})
			},
			expectError:       true,
			expectedErrorCode: codes.Unauthenticated,
			expectedErrorMsg:  "missing x-authorization-timestamp header",
			validateIdentity:  false,
		},
		{
			name: "missing signature header returns Unauthenticated",
			setupMetadata: func() metadata.MD {
				timestampMs := time.Now().UnixMilli()
				return metadata.New(map[string]string{
					hmacutil.HeaderAuthorization: testAPIKey1,
					hmacutil.HeaderTimestamp:     strconv.FormatInt(timestampMs, 10),
				})
			},
			expectError:       true,
			expectedErrorCode: codes.Unauthenticated,
			expectedErrorMsg:  "missing x-authorization-signature-sha256 header",
			validateIdentity:  false,
		},
		{
			name: "invalid api key returns Unauthenticated",
			setupMetadata: func() metadata.MD {
				timestampMs := time.Now().UnixMilli()
				apiKey := "invalid-api-key"
				secret := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
				signature := generateTestSignature(t, secret, method, req, apiKey, timestampMs)
				return metadata.New(map[string]string{
					hmacutil.HeaderAuthorization: apiKey,
					hmacutil.HeaderTimestamp:     strconv.FormatInt(timestampMs, 10),
					hmacutil.HeaderSignature:     signature,
				})
			},
			expectError:       true,
			expectedErrorCode: codes.Unauthenticated,
			expectedErrorMsg:  "invalid credentials",
			validateIdentity:  false,
		},
		{
			name: "expired timestamp returns Unauthenticated",
			setupMetadata: func() metadata.MD {
				expiredTimestamp := time.Now().Add(-20 * time.Second).UnixMilli()
				apiKey := testAPIKey1
				secret := testSecretCurrent1
				signature := generateTestSignature(t, secret, method, req, apiKey, expiredTimestamp)
				return metadata.New(map[string]string{
					hmacutil.HeaderAuthorization: apiKey,
					hmacutil.HeaderTimestamp:     strconv.FormatInt(expiredTimestamp, 10),
					hmacutil.HeaderSignature:     signature,
				})
			},
			expectError:       true,
			expectedErrorCode: codes.Unauthenticated,
			expectedErrorMsg:  "invalid or expired timestamp",
			validateIdentity:  false,
		},
		{
			name: "different client with different secret sets correct identity",
			setupMetadata: func() metadata.MD {
				timestampMs := time.Now().UnixMilli()
				apiKey := "00000000-0000-0000-0000-000000000002"
				secret := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
				signature := generateTestSignature(t, secret, method, req, apiKey, timestampMs)
				return metadata.New(map[string]string{
					hmacutil.HeaderAuthorization: apiKey,
					hmacutil.HeaderTimestamp:     strconv.FormatInt(timestampMs, 10),
					hmacutil.HeaderSignature:     signature,
				})
			},
			expectError:      false,
			validateIdentity: true,
			expectedClientID: "client-2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctx context.Context
			md := tt.setupMetadata()
			if md != nil {
				ctx = metadata.NewIncomingContext(context.Background(), md)
			} else {
				ctx = context.Background()
			}

			capturingHandler := &contextCapturingHandler{}
			resp, err := middleware.Intercept(ctx, req, info, capturingHandler.Handle)

			if tt.expectError {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, tt.expectedErrorCode, st.Code())
				require.Contains(t, st.Message(), tt.expectedErrorMsg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
			}

			if tt.validateIdentity {
				require.NotNil(t, capturingHandler.capturedCtx)
				identity, ok := auth.IdentityFromContext(capturingHandler.capturedCtx)
				require.True(t, ok, "CallerIdentity should be set in context")
				require.Equal(t, tt.expectedClientID, identity.CallerID)
			}
		})
	}
}
