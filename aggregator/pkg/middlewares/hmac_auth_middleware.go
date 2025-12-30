package middlewares

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/smartcontractkit/chainlink-ccv/common/auth"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type HMACAuthMiddleware struct {
	hmac   auth.HMACAuth
	logger logger.Logger
}

// NewHMACAuthMiddleware creates a new HMAC authentication middleware.
func NewHMACAuthMiddleware(config *auth.APIKeyConfig, lggr logger.Logger) *HMACAuthMiddleware {
	return &HMACAuthMiddleware{
		hmac:   *auth.NewHMACAuth(config, lggr),
		logger: lggr,
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

	body, err := hmac.SerializeRequestBody(req)
	if err != nil {
		m.logger.Error("Unable to seralize request body")
		// Pass through to other auth mechanisms
		return handler(ctx, req)
	}

	ctx, err = m.hmac.Authorize(ctx, body, hmac.HTTPMethodPost, info.FullMethod, apiKey, timestamp, providedSignature)
	if err != nil {
		return nil, err
	}

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
