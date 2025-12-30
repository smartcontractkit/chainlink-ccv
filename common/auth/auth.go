package auth

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type HMACAuth struct {
	config *APIKeyConfig
	logger logger.Logger
}

func NewHMACAuth(config *APIKeyConfig, lggr logger.Logger) *HMACAuth {
	return &HMACAuth{
		config: config,
		logger: lggr,
	}
}

func (h *HMACAuth) Authorize(ctx context.Context, body protocol.ByteSlice, method, path, apiKey, timestamp, signature string) (context.Context, error) {
	if err := validateParams(h.logger, apiKey, timestamp, signature); err != nil {
		return nil, err
	}

	client, exists := h.config.GetClientByAPIKey(apiKey)
	if !exists {
		h.logger.Warnf("Authentication failed: invalid or disabled API key")
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	if len(client.Secrets) == 0 {
		h.logger.Errorf("Client %s has no secrets configured", client.ClientID)
		return nil, status.Error(codes.Internal, "authentication configuration error")
	}

	if err := hmac.ValidateTimestamp(timestamp); err != nil {
		h.logger.Warnf("Authentication failed for client %s: %v", client.ClientID, err)
		return nil, status.Error(codes.Unauthenticated, "invalid or expired timestamp")
	}

	bodyHash := hmac.ComputeBodyHash(body)
	stringToSign := hmac.GenerateStringToSign(method, path, bodyHash, apiKey, timestamp)

	if !hmac.ValidateSignature(stringToSign, signature, client.Secrets) {
		h.logger.Warnf("Authentication failed for client %s: invalid signature", client.ClientID)
		return nil, status.Error(codes.Unauthenticated, "invalid signature")
	}

	identity := CreateCallerIdentity(client.ClientID, false)
	h.logger.Debugf("Successfully authenticated client: %s", client.ClientID)

	return ToContext(ctx, identity), nil
}

func validateParams(logger logger.Logger, apiKey, timestamp, signature string) error {
	if apiKey == "" {
		logger.Warnf("Authentication failed: missing api key")
		return status.Error(codes.Unauthenticated, "missing api key")
	}
	if timestamp == "" {
		logger.Warnf("Authentication failed: missing timestamp")
		return status.Error(codes.Unauthenticated, "missing timestamp")
	}
	if signature == "" {
		logger.Warnf("Authentication failed: missing signature")
		return status.Error(codes.Unauthenticated, "missing signature")
	}

	return nil
}
