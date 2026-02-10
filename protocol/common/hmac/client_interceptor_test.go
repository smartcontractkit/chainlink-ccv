package hmac

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

var testCredentials, _ = GenerateCredentials()

func TestNewClientInterceptor(t *testing.T) {
	config := &ClientConfig{
		APIKey: testCredentials.APIKey,
		Secret: testCredentials.Secret,
	}

	t.Run("adds HMAC headers to request", func(t *testing.T) {
		interceptor := NewClientInterceptor(config)
		ctx := context.Background()
		req := &emptypb.Empty{}

		var capturedCtx context.Context
		mockInvoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			capturedCtx = ctx //nolint:fatcontext // test helper needs to capture context for assertion
			return nil
		}

		err := interceptor(ctx, "/test.Service/Method", req, nil, nil, mockInvoker)
		require.NoError(t, err)

		// Verify HMAC headers were added
		md, ok := metadata.FromOutgoingContext(capturedCtx)
		require.True(t, ok, "metadata should be present")

		authHeaders := md.Get(HeaderAuthorization)
		require.Len(t, authHeaders, 1, "should have authorization header")
		require.Equal(t, config.APIKey, authHeaders[0], "API key should match")

		timestampHeaders := md.Get(HeaderTimestamp)
		require.Len(t, timestampHeaders, 1, "should have timestamp header")

		signatureHeaders := md.Get(HeaderSignature)
		require.Len(t, signatureHeaders, 1, "should have signature header")
	})

	t.Run("preserves existing metadata", func(t *testing.T) {
		interceptor := NewClientInterceptor(config)

		// Create context with existing metadata
		existingMD := metadata.Pairs("committee", "secondary", "custom-header", "custom-value")
		ctx := metadata.NewOutgoingContext(context.Background(), existingMD)
		req := &emptypb.Empty{}

		var capturedCtx context.Context
		mockInvoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			capturedCtx = ctx //nolint:fatcontext // test helper needs to capture context for assertion
			return nil
		}

		err := interceptor(ctx, "/test.Service/Method", req, nil, nil, mockInvoker)
		require.NoError(t, err)

		// Verify both existing and HMAC headers are present
		md, ok := metadata.FromOutgoingContext(capturedCtx)
		require.True(t, ok, "metadata should be present")

		// Check existing metadata preserved
		committeeHeaders := md.Get("committee")
		require.Len(t, committeeHeaders, 1, "should have committee header")
		require.Equal(t, "secondary", committeeHeaders[0], "committee value should match")

		customHeaders := md.Get("custom-header")
		require.Len(t, customHeaders, 1, "should have custom header")
		require.Equal(t, "custom-value", customHeaders[0], "custom value should match")

		// Check HMAC headers added
		authHeaders := md.Get(HeaderAuthorization)
		require.Len(t, authHeaders, 1, "should have authorization header")
		require.Equal(t, config.APIKey, authHeaders[0], "API key should match")

		signatureHeaders := md.Get(HeaderSignature)
		require.Len(t, signatureHeaders, 1, "should have signature header")
	})

	t.Run("does not override existing HMAC headers", func(t *testing.T) {
		interceptor := NewClientInterceptor(config)

		// Create context with existing HMAC headers
		existingMD := metadata.Pairs(
			HeaderAuthorization, "existing-api-key",
			HeaderTimestamp, "1234567890",
			HeaderSignature, "existing-signature",
		)
		ctx := metadata.NewOutgoingContext(context.Background(), existingMD)
		req := &emptypb.Empty{}

		var capturedCtx context.Context
		mockInvoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			capturedCtx = ctx //nolint:fatcontext // test helper needs to capture context for assertion
			return nil
		}

		err := interceptor(ctx, "/test.Service/Method", req, nil, nil, mockInvoker)
		require.NoError(t, err)

		// Verify original HMAC headers were preserved (not replaced)
		md, ok := metadata.FromOutgoingContext(capturedCtx)
		require.True(t, ok, "metadata should be present")

		authHeaders := md.Get(HeaderAuthorization)
		require.Len(t, authHeaders, 1, "should have authorization header")
		require.Equal(t, "existing-api-key", authHeaders[0], "should preserve existing API key")

		timestampHeaders := md.Get(HeaderTimestamp)
		require.Len(t, timestampHeaders, 1, "should have timestamp header")
		require.Equal(t, "1234567890", timestampHeaders[0], "should preserve existing timestamp")

		signatureHeaders := md.Get(HeaderSignature)
		require.Len(t, signatureHeaders, 1, "should have signature header")
		require.Equal(t, "existing-signature", signatureHeaders[0], "should preserve existing signature")
	})

	t.Run("generates valid signature", func(t *testing.T) {
		interceptor := NewClientInterceptor(config)
		ctx := context.Background()
		req := &emptypb.Empty{}

		var capturedCtx context.Context
		mockInvoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			capturedCtx = ctx //nolint:fatcontext // test helper needs to capture context for assertion
			return nil
		}

		err := interceptor(ctx, "/test.Service/Method", req, nil, nil, mockInvoker)
		require.NoError(t, err)

		// Extract headers and validate signature
		md, ok := metadata.FromOutgoingContext(capturedCtx)
		require.True(t, ok, "metadata should be present")

		apiKey := md.Get(HeaderAuthorization)[0]
		timestamp := md.Get(HeaderTimestamp)[0]
		signature := md.Get(HeaderSignature)[0]

		// Reconstruct the signature and verify it matches
		body, err := proto.Marshal(req)
		require.NoError(t, err)

		bodyHash := ComputeBodyHash(body)
		stringToSign := GenerateStringToSign(HTTPMethodPost, "/test.Service/Method", bodyHash, apiKey, timestamp)
		expectedSignature, err := ComputeHMAC(config.Secret, stringToSign)
		require.NoError(t, err)

		require.Equal(t, expectedSignature, signature, "signature should be valid")
	})

	t.Run("timestamp is current", func(t *testing.T) {
		interceptor := NewClientInterceptor(config)
		ctx := context.Background()
		req := &emptypb.Empty{}

		beforeTime := time.Now().UnixMilli()

		var capturedCtx context.Context
		mockInvoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			capturedCtx = ctx //nolint:fatcontext // test helper needs to capture context for assertion
			return nil
		}

		err := interceptor(ctx, "/test.Service/Method", req, nil, nil, mockInvoker)
		require.NoError(t, err)

		afterTime := time.Now().UnixMilli()

		// Extract timestamp and verify it's current
		md, ok := metadata.FromOutgoingContext(capturedCtx)
		require.True(t, ok, "metadata should be present")

		timestampStr := md.Get(HeaderTimestamp)[0]
		err = ValidateTimestamp(timestampStr)
		require.NoError(t, err, "timestamp should be valid")

		// Verify timestamp is within the call window
		timestampMs := mustParseInt64(t, timestampStr)
		require.GreaterOrEqual(t, timestampMs, beforeTime, "timestamp should be after call started")
		require.LessOrEqual(t, timestampMs, afterTime, "timestamp should be before call finished")
	})

	t.Run("returns error for non-proto message", func(t *testing.T) {
		interceptor := NewClientInterceptor(config)
		ctx := context.Background()

		// Pass a non-proto message
		notProtoReq := "not a proto message"

		mockInvoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			return nil
		}

		err := interceptor(ctx, "/test.Service/Method", notProtoReq, nil, nil, mockInvoker)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a proto.Message")
	})
}

func mustParseInt64(t *testing.T, s string) int64 {
	t.Helper()
	var result int64
	_, err := fmt.Sscanf(s, "%d", &result)
	require.NoError(t, err)
	return result
}
