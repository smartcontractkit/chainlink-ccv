package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage"
	pb "github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

// WriteBlockCheckpointHandler handles WriteBlockCheckpoint gRPC requests.
type WriteBlockCheckpointHandler struct {
	storage          *storage.CheckpointStorage
	apiConfig        *model.APIKeyConfig     // Optional API key configuration for enhanced validation
	checkpointConfig *model.CheckpointConfig // Optional checkpoint configuration for limits
}

// NewWriteBlockCheckpointHandler creates a new WriteBlockCheckpointHandler with configuration.
func NewWriteBlockCheckpointHandler(storage *storage.CheckpointStorage, apiConfig *model.APIKeyConfig, checkpointConfig *model.CheckpointConfig) *WriteBlockCheckpointHandler {
	return &WriteBlockCheckpointHandler{
		storage:          storage,
		apiConfig:        apiConfig,
		checkpointConfig: checkpointConfig,
	}
}

// Handle processes a WriteBlockCheckpoint request.
func (h *WriteBlockCheckpointHandler) Handle(ctx context.Context, req *pb.WriteBlockCheckpointRequest) (*pb.WriteBlockCheckpointResponse, error) {
	var clientID string
	var err error

	// Use configuration-based authentication if clients are configured, otherwise fall back to basic
	if h.apiConfig != nil && len(h.apiConfig.Clients) > 0 {
		_, clientID, err = extractAPIKeyWithConfig(ctx, h.apiConfig)
		if err != nil {
			return model.NewWriteBlockCheckpointResponse(false), handleAuthenticationError(err)
		}
	} else {
		// Fallback to basic API key validation and use API key as client ID
		apiKey, err := extractAPIKey(ctx)
		if err != nil {
			return model.NewWriteBlockCheckpointResponse(false), handleAuthenticationError(err)
		}
		clientID = apiKey
	}

	// Validate the request (use config limits if available)
	if err := h.validateRequest(req); err != nil {
		return model.NewWriteBlockCheckpointResponse(false), handleValidationError(err)
	}

	// Convert protobuf checkpoints to storage format
	checkpointMap := model.ProtoCheckpointsToMap(req.Checkpoints)

	// Store checkpoints using the client ID
	if err := h.storage.StoreCheckpoints(clientID, checkpointMap); err != nil {
		return model.NewWriteBlockCheckpointResponse(false), handleInternalError(err)
	}

	return model.NewWriteBlockCheckpointResponse(true), nil
}

// validateRequest validates the request using configuration limits if available.
func (h *WriteBlockCheckpointHandler) validateRequest(req *pb.WriteBlockCheckpointRequest) error {
	if req == nil {
		return model.ValidateWriteBlockCheckpointRequest(req) // Basic validation
	}

	// Use configuration limits if available
	if h.checkpointConfig != nil && len(req.Checkpoints) > h.checkpointConfig.MaxCheckpointsPerRequest {
		return model.ValidateWriteBlockCheckpointRequest(req) // This will catch the limit
	}

	return model.ValidateWriteBlockCheckpointRequest(req)
}
