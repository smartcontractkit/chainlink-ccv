package middlewares

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type HMACAuthMiddleware struct {
	clientProvider auth.ClientProvider
	logger         logger.Logger
}

// NewHMACAuthMiddleware creates a new HMAC authentication middleware.
func NewHMACAuthMiddleware(config auth.ClientProvider, lggr logger.Logger) *HMACAuthMiddleware {
	return &HMACAuthMiddleware{
		clientProvider: config,
		logger:         lggr,
	}
}

func (m *HMACAuthMiddleware) Intercept(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return handler(ctx, req)
	}

	apiKey := getMetadataValue(md, hmac.HeaderAuthorization)
	timestamp := getMetadataValue(md, hmac.HeaderTimestamp)
	providedSignature := getMetadataValue(md, hmac.HeaderSignature)

	// If no HMAC headers are present, pass through to allow other auth mechanisms
	if apiKey == "" && timestamp == "" && providedSignature == "" {
		m.logger.Debugf("No HMAC headers present, passing through to next middleware")
		return handler(ctx, req)
	}

	// If some but not all HMAC headers are present, this is an error
	if apiKey == "" {
		m.logger.Warnf("Authentication failed: missing authorization header")
		return nil, status.Error(codes.Unauthenticated, "missing authorization header")
	}
	if timestamp == "" {
		m.logger.Warnf("Authentication failed: missing x-authorization-timestamp header")
		return nil, status.Error(codes.Unauthenticated, "missing x-authorization-timestamp header")
	}
	if providedSignature == "" {
		m.logger.Warnf("Authentication failed: missing x-authorization-signature-sha256 header")
		return nil, status.Error(codes.Unauthenticated, "missing x-authorization-signature-sha256 header")
	}

	client, pair, exists := m.clientProvider.GetClientByAPIKey(apiKey)
	if !exists {
		m.logger.Warnf("Authentication failed: invalid or disabled API key")
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	if err := hmac.ValidateTimestamp(timestamp); err != nil {
		m.logger.Warnf("Authentication failed for client %s: %v", client.GetClientID(), err)
		return nil, status.Error(codes.Unauthenticated, "invalid or expired timestamp")
	}

	body, err := hmac.SerializeRequestBody(req)
	if err != nil {
		m.logger.Errorf("Failed to serialize request body: %v", err)
		return nil, status.Error(codes.Internal, "request serialization error")
	}

	bodyHash := hmac.ComputeBodyHash(body)

	stringToSign := hmac.GenerateStringToSign(hmac.HTTPMethodPost, info.FullMethod, bodyHash, apiKey, timestamp)

	if !hmac.ValidateSignature(stringToSign, providedSignature, pair.GetSecret()) {
		m.logger.Warnf("Authentication failed for client %s: invalid signature", client.GetClientID())
		return nil, status.Error(codes.Unauthenticated, "invalid signature")
	}

	identity := auth.CreateCallerIdentity(client.GetClientID(), false)
	ctx = auth.ToContext(ctx, identity)

	m.logger.Debugf("Successfully authenticated client: %s", client.GetClientID())

	return handler(ctx, req)
}

// getMetadataValue safely extracts a single value from gRPC metadata.
func getMetadataValue(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
