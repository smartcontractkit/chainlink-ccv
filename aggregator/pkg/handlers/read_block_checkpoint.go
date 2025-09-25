package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// ReadBlockCheckpointHandler handles ReadBlockCheckpoint gRPC requests.
type ReadBlockCheckpointHandler struct {
	storage   *storage.CheckpointStorage
	apiConfig *model.APIKeyConfig // Optional API key configuration for enhanced validation
}

// NewReadBlockCheckpointHandler creates a new ReadBlockCheckpointHandler with configuration.
func NewReadBlockCheckpointHandler(storage *storage.CheckpointStorage, apiConfig *model.APIKeyConfig) *ReadBlockCheckpointHandler {
	return &ReadBlockCheckpointHandler{
		storage:   storage,
		apiConfig: apiConfig,
	}
}

// Handle processes a ReadBlockCheckpoint request.
func (h *ReadBlockCheckpointHandler) Handle(ctx context.Context, req *pb.ReadBlockCheckpointRequest) (*pb.ReadBlockCheckpointResponse, error) {
	var clientID string
	var err error

	// Use configuration-based authentication if clients are configured, otherwise fall back to basic
	if h.apiConfig != nil && len(h.apiConfig.Clients) > 0 {
		_, clientID, err = extractAPIKeyWithConfig(ctx, h.apiConfig)
		if err != nil {
			return nil, handleAuthenticationError(err)
		}
	} else {
		// Fallback to basic API key validation and use API key as client ID
		apiKey, err := extractAPIKey(ctx)
		if err != nil {
			return nil, handleAuthenticationError(err)
		}
		clientID = apiKey
	}

	// Validate the request (minimal validation required for read)
	if err := model.ValidateReadBlockCheckpointRequest(req); err != nil {
		return nil, handleValidationError(err)
	}

	// Retrieve checkpoints for this client
	checkpointMap := h.storage.GetClientCheckpoints(clientID)

	// Convert storage format to protobuf checkpoints
	protoCheckpoints := model.MapToProtoCheckpoints(checkpointMap)

	return model.NewReadBlockCheckpointResponse(protoCheckpoints), nil
}
