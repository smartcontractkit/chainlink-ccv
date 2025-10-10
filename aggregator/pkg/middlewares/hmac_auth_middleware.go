package middlewares

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pkg/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type HMACAuthMiddleware struct {
	apiKeyConfig *model.APIKeyConfig
	logger       logger.Logger
}

// NewHMACAuthMiddleware creates a new HMAC authentication middleware.
func NewHMACAuthMiddleware(config *model.APIKeyConfig, lggr logger.Logger) *HMACAuthMiddleware {
	return &HMACAuthMiddleware{
		apiKeyConfig: config,
		logger:       lggr,
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
		return nil, status.Error(codes.Unauthenticated, "missing authorization header")
	}
	if timestamp == "" {
		return nil, status.Error(codes.Unauthenticated, "missing x-authorization-timestamp header")
	}
	if providedSignature == "" {
		return nil, status.Error(codes.Unauthenticated, "missing x-authorization-signature-sha256 header")
	}

	client, exists := m.apiKeyConfig.GetClientByAPIKey(apiKey)
	if !exists {
		m.logger.Warnf("Authentication failed: invalid or disabled API key")
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	if len(client.Secrets) == 0 {
		m.logger.Errorf("Client %s has no secrets configured", client.ClientID)
		return nil, status.Error(codes.Internal, "authentication configuration error")
	}

	if err := hmac.ValidateTimestamp(timestamp); err != nil {
		m.logger.Warnf("Authentication failed for client %s: %v", client.ClientID, err)
		return nil, status.Error(codes.Unauthenticated, "invalid or expired timestamp")
	}

	body, err := hmac.SerializeRequestBody(req)
	if err != nil {
		m.logger.Errorf("Failed to serialize request body: %v", err)
		return nil, status.Error(codes.Internal, "request serialization error")
	}

	bodyHash := hmac.ComputeBodyHash(body)

	stringToSign := hmac.GenerateStringToSign(hmac.HTTPMethodPost, info.FullMethod, bodyHash, apiKey, timestamp)

	if !hmac.ValidateSignature(stringToSign, providedSignature, client.Secrets) {
		m.logger.Warnf("Authentication failed for client %s: invalid signature", client.ClientID)
		return nil, status.Error(codes.Unauthenticated, "invalid signature")
	}

	identity := auth.CreateCallerIdentity(client.ClientID, false)
	ctx = auth.ToContext(ctx, identity)

	m.logger.Debugf("Successfully authenticated client: %s", client.ClientID)

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
