package hmac

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// ClientConfig holds the configuration for HMAC authentication in clients.
type ClientConfig struct {
	// APIKey is the client's API key (UUID format)
	APIKey string
	// Secret is the HMAC secret used to sign requests
	Secret string
}

// NewClientInterceptor creates a gRPC unary client interceptor that automatically adds HMAC authentication headers
// to all outgoing requests.
//
// The interceptor will:
// 1. Check if the context already has HMAC authentication headers - if so, it won't override them
// 2. Generate a timestamp and serialize the request body
// 3. Compute the HMAC signature using the provided credentials
// 4. Add authentication headers (authorization, x-authorization-timestamp, x-authorization-signature-sha256) to the request
// 5. Preserve any existing metadata in the context (e.g., committee, custom headers)
//
// Usage:
//
//	config := &hmac.ClientConfig{
//	    APIKey: "your-api-key",
//	    Secret: "your-secret",
//	}
//
//	conn, err := grpc.Dial(
//	    "localhost:50051",
//	    grpc.WithInsecure(),
//	    grpc.WithUnaryInterceptor(hmac.NewClientInterceptor(config)),
//	)
func NewClientInterceptor(config *ClientConfig) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		// Check if context already has authentication headers - if so, don't override them
		// This allows manual signature generation or per-request credential overrides
		if md, ok := metadata.FromOutgoingContext(ctx); ok {
			if len(md.Get(HeaderAuthorization)) > 0 ||
				len(md.Get(HeaderTimestamp)) > 0 ||
				len(md.Get(HeaderSignature)) > 0 {
				// Context already has HMAC headers, don't override
				return invoker(ctx, method, req, reply, cc, opts...)
			}
		}

		// Generate HMAC signature
		timestampMs := time.Now().UnixMilli()

		// Serialize the request body
		protoReq, ok := req.(proto.Message)
		if !ok {
			return fmt.Errorf("request is not a proto.Message")
		}

		signature, err := GenerateSignature(config.Secret, method, protoReq, config.APIKey, timestampMs)
		if err != nil {
			return fmt.Errorf("failed to generate HMAC signature: %w", err)
		}

		// Add HMAC headers to the context, preserving any existing metadata
		hmacMD := metadata.Pairs(
			HeaderAuthorization, config.APIKey,
			HeaderTimestamp, strconv.FormatInt(timestampMs, 10),
			HeaderSignature, signature,
		)

		// Merge with existing metadata if present
		if existingMD, ok := metadata.FromOutgoingContext(ctx); ok {
			hmacMD = metadata.Join(existingMD, hmacMD)
		}

		ctx = metadata.NewOutgoingContext(ctx, hmacMD)

		// Invoke the RPC with the authenticated context
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
