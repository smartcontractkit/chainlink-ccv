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
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

const (
	testAPIKey1            = "test-api-key-1"
	testSecretCurrent1     = "secret-current-1"
	testAdminAPIKey        = "admin-api-key"
	testAdminSecretCurrent = "admin-secret-current"
)

// Test helper: generates HMAC signature for a gRPC request following Data Streams pattern.
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

// Test helper: creates test API key configuration.
func createTestAPIKeyConfig() *model.APIKeyConfig {
	return &model.APIKeyConfig{
		Clients: map[string]*model.APIClient{
			testAPIKey1: {
				ClientID:    "client-1",
				Description: "Test client 1",
				Enabled:     true,
				IsAdmin:     false,
				Secrets: map[string]string{
					"current":  testSecretCurrent1,
					"previous": "secret-old-1",
				},
			},
			"test-api-key-2": {
				ClientID:    "client-2",
				Description: "Test client 2",
				Enabled:     true,
				IsAdmin:     false,
				Secrets: map[string]string{
					"current": "secret-current-2",
				},
			},
			testAdminAPIKey: {
				ClientID:    "admin-client",
				Description: "Test admin client",
				Enabled:     true,
				IsAdmin:     true,
				Secrets: map[string]string{
					"current": testAdminSecretCurrent,
				},
			},
		},
	}
}

// Test helper: mock handler that captures context for identity verification.
type contextCapturingHandler struct {
	capturedCtx context.Context //nolint:containedctx // test helper needs to capture context for assertion
}

func (h *contextCapturingHandler) Handle(ctx context.Context, req any) (any, error) {
	h.capturedCtx = ctx //nolint:fatcontext // test helper needs to capture context for assertion
	return &committeepb.ReadChainStatusResponse{Statuses: []*committeepb.ChainStatus{}}, nil
}

func TestHMACAuthMiddleware(t *testing.T) {
	config := createTestAPIKeyConfig()
	lggr := logger.Test(t)
	middleware := NewHMACAuthMiddleware(config, lggr)

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
				secret := "some-secret"
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
			name: "key rotation - valid signature with previous secret and sets correct identity",
			setupMetadata: func() metadata.MD {
				timestampMs := time.Now().UnixMilli()
				apiKey := testAPIKey1
				oldSecret := "secret-old-1"
				signature := generateTestSignature(t, oldSecret, method, req, apiKey, timestampMs)
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
			name: "different client with different secret sets correct identity",
			setupMetadata: func() metadata.MD {
				timestampMs := time.Now().UnixMilli()
				apiKey := "test-api-key-2"
				secret := "secret-current-2"
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

func TestHMACAuthMiddleware_AdminFunctionality(t *testing.T) {
	config := createTestAPIKeyConfig()
	lggr := logger.Test(t)
	middleware := NewHMACAuthMiddleware(config, lggr)

	req := &committeepb.WriteChainStatusRequest{}
	method := "/Aggregator/WriteChainStatus"
	info := &grpc.UnaryServerInfo{FullMethod: method}

	tests := []struct {
		name                string
		setupMetadata       func() metadata.MD
		expectError         bool
		expectedErrorCode   codes.Code
		expectedErrorMsg    string
		expectAdmin         bool
		expectedCallerID    string
		expectedEffectiveID string
		expectOnBehalfOf    bool
	}{
		{
			name: "admin client without on-behalf-of header acts normally",
			setupMetadata: func() metadata.MD {
				timestampMs := time.Now().UnixMilli()
				apiKey := testAdminAPIKey
				secret := testAdminSecretCurrent
				signature := generateTestSignature(t, secret, method, req, apiKey, timestampMs)
				return metadata.New(map[string]string{
					hmacutil.HeaderAuthorization: apiKey,
					hmacutil.HeaderTimestamp:     strconv.FormatInt(timestampMs, 10),
					hmacutil.HeaderSignature:     signature,
				})
			},
			expectError:         false,
			expectAdmin:         true,
			expectedCallerID:    "admin-client",
			expectedEffectiveID: "admin-client",
			expectOnBehalfOf:    false,
		},
		{
			name: "admin client with on-behalf-of header sets effective caller ID",
			setupMetadata: func() metadata.MD {
				timestampMs := time.Now().UnixMilli()
				apiKey := testAdminAPIKey
				secret := testAdminSecretCurrent
				signature := generateTestSignature(t, secret, method, req, apiKey, timestampMs)
				return metadata.New(map[string]string{
					hmacutil.HeaderAuthorization: apiKey,
					hmacutil.HeaderTimestamp:     strconv.FormatInt(timestampMs, 10),
					hmacutil.HeaderSignature:     signature,
					"x-admin-client-id":          "target-verifier",
				})
			},
			expectError:         false,
			expectAdmin:         true,
			expectedCallerID:    "admin-client",
			expectedEffectiveID: "target-verifier",
			expectOnBehalfOf:    true,
		},
		{
			name: "regular client with on-behalf-of header is denied",
			setupMetadata: func() metadata.MD {
				timestampMs := time.Now().UnixMilli()
				apiKey := testAPIKey1
				secret := testSecretCurrent1
				signature := generateTestSignature(t, secret, method, req, apiKey, timestampMs)
				return metadata.New(map[string]string{
					hmacutil.HeaderAuthorization: apiKey,
					hmacutil.HeaderTimestamp:     strconv.FormatInt(timestampMs, 10),
					hmacutil.HeaderSignature:     signature,
					"x-admin-client-id":          "target-verifier",
				})
			},
			expectError:       true,
			expectedErrorCode: codes.PermissionDenied,
			expectedErrorMsg:  "only admin clients can perform operations on behalf of other clients",
			expectAdmin:       false,
		},
		{
			name: "regular client without on-behalf-of header works normally",
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
			expectError:         false,
			expectAdmin:         false,
			expectedCallerID:    "client-1",
			expectedEffectiveID: "client-1",
			expectOnBehalfOf:    false,
		},
		{
			name: "admin with empty on-behalf-of header acts normally",
			setupMetadata: func() metadata.MD {
				timestampMs := time.Now().UnixMilli()
				apiKey := testAdminAPIKey
				secret := testAdminSecretCurrent
				signature := generateTestSignature(t, secret, method, req, apiKey, timestampMs)
				return metadata.New(map[string]string{
					hmacutil.HeaderAuthorization: apiKey,
					hmacutil.HeaderTimestamp:     strconv.FormatInt(timestampMs, 10),
					hmacutil.HeaderSignature:     signature,
					"x-admin-client-id":          "",
				})
			},
			expectError:         false,
			expectAdmin:         true,
			expectedCallerID:    "admin-client",
			expectedEffectiveID: "admin-client",
			expectOnBehalfOf:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := tt.setupMetadata()
			ctx := metadata.NewIncomingContext(context.Background(), md)

			capturingHandler := &contextCapturingHandler{}
			resp, err := middleware.Intercept(ctx, req, info, capturingHandler.Handle)

			if tt.expectError {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, tt.expectedErrorCode, st.Code())
				require.Contains(t, st.Message(), tt.expectedErrorMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			// Validate identity was set correctly
			require.NotNil(t, capturingHandler.capturedCtx)
			identity, ok := auth.IdentityFromContext(capturingHandler.capturedCtx)
			require.True(t, ok, "CallerIdentity should be set in context")

			require.Equal(t, tt.expectedCallerID, identity.CallerID)
			require.Equal(t, tt.expectedEffectiveID, identity.EffectiveCallerID)
			require.Equal(t, tt.expectAdmin, identity.IsAdmin)

			if tt.expectOnBehalfOf {
				// When acting on behalf of someone, the effective ID should differ from caller ID
				require.NotEqual(t, identity.CallerID, identity.EffectiveCallerID)
			} else {
				// When not acting on behalf of someone, they should be the same
				require.Equal(t, identity.CallerID, identity.EffectiveCallerID)
			}
		})
	}
}
