package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// extractAPIKey extracts and validates the API key from gRPC metadata.
// Uses basic validation - for production use extractAPIKeyWithConfig.
func extractAPIKey(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "metadata required")
	}

	apiKeys := md["api-key"]
	if len(apiKeys) == 0 {
		return "", status.Error(codes.Unauthenticated, "api key required")
	}

	apiKey := apiKeys[0]
	if err := model.ValidateAPIKey(apiKey); err != nil {
		return "", status.Error(codes.Unauthenticated, err.Error())
	}

	return apiKey, nil
}

// extractAPIKeyWithConfig extracts and validates the API key using configuration.
// Returns the API key and the corresponding client ID.
func extractAPIKeyWithConfig(ctx context.Context, config *model.APIKeyConfig) (string, string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", "", status.Error(codes.Unauthenticated, "metadata required")
	}

	apiKeys := md["api-key"]
	if len(apiKeys) == 0 {
		return "", "", status.Error(codes.Unauthenticated, "api key required")
	}

	apiKey := apiKeys[0]
	if err := config.ValidateAPIKey(apiKey); err != nil {
		return "", "", status.Error(codes.Unauthenticated, err.Error())
	}

	client, _ := config.GetClientByAPIKey(apiKey)
	return apiKey, client.ClientID, nil
}

// handleAuthenticationError creates a consistent error response for authentication failures.
func handleAuthenticationError(err error) error {
	if err == nil {
		return nil
	}

	return err
}

// handleValidationError creates a consistent error response for validation failures.
func handleValidationError(err error) error {
	if err == nil {
		return nil
	}

	return status.Error(codes.InvalidArgument, err.Error())
}

// handleInternalError creates a consistent error response for internal failures.
func handleInternalError(err error) error {
	if err == nil {
		return nil
	}

	return status.Error(codes.Internal, err.Error())
}
