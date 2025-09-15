package model

import (
	"errors"
	"fmt"
	"strings"

	pb "github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

// ValidateBlockCheckpoint validates a single block checkpoint.
func ValidateBlockCheckpoint(checkpoint *pb.BlockCheckpoint) error {
	if checkpoint == nil {
		return errors.New("checkpoint cannot be nil")
	}

	if checkpoint.ChainSelector == 0 {
		return errors.New("chain_selector must be greater than 0")
	}

	if checkpoint.FinalizedBlockHeight == 0 {
		return errors.New("finalized_block_height must be greater than 0")
	}

	return nil
}

// ValidateWriteBlockCheckpointRequest validates the WriteBlockCheckpointRequest.
func ValidateWriteBlockCheckpointRequest(req *pb.WriteBlockCheckpointRequest) error {
	if req == nil {
		return errors.New("request cannot be nil")
	}

	if req.Checkpoints == nil || len(req.Checkpoints) == 0 {
		return errors.New("at least one checkpoint required")
	}

	if len(req.Checkpoints) > 1000 {
		return errors.New("maximum 1000 checkpoints per request")
	}

	// Validate each checkpoint in the request
	for i, checkpoint := range req.Checkpoints {
		if err := ValidateBlockCheckpoint(checkpoint); err != nil {
			return fmt.Errorf("checkpoint[%d]: %w", i, err)
		}
	}

	return nil
}

// ValidateReadBlockCheckpointRequest validates the ReadBlockCheckpointRequest.
func ValidateReadBlockCheckpointRequest(req *pb.ReadBlockCheckpointRequest) error {
	if req == nil {
		return errors.New("request cannot be nil")
	}

	// ReadBlockCheckpoint has no additional validation requirements beyond authentication
	return nil
}

// ValidateAPIKey validates that an API key is not empty and not too long.
// This is a basic validation - for configuration-based validation use CheckpointConfig.ValidateAPIKey.
func ValidateAPIKey(apiKey string) error {
	if strings.TrimSpace(apiKey) == "" {
		return errors.New("api key cannot be empty")
	}

	if len(apiKey) > 1000 {
		return errors.New("api key too long")
	}

	return nil
}

// ProtoCheckpointsToMap converts protobuf checkpoints to a map for storage.
func ProtoCheckpointsToMap(protoCheckpoints []*pb.BlockCheckpoint) map[uint64]uint64 {
	result := make(map[uint64]uint64, len(protoCheckpoints))

	for _, checkpoint := range protoCheckpoints {
		if checkpoint != nil {
			result[checkpoint.ChainSelector] = checkpoint.FinalizedBlockHeight
		}
	}

	return result
}

// MapToProtoCheckpoints converts a storage map to protobuf checkpoints.
// Results are sorted by chain_selector for deterministic ordering.
func MapToProtoCheckpoints(checkpoints map[uint64]uint64) []*pb.BlockCheckpoint {
	result := make([]*pb.BlockCheckpoint, 0, len(checkpoints))

	for chainSelector, blockHeight := range checkpoints {
		result = append(result, &pb.BlockCheckpoint{
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: blockHeight,
		})
	}

	// Sort by chain selector for deterministic ordering
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].ChainSelector > result[j].ChainSelector {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}

// NewWriteBlockCheckpointResponse creates a WriteBlockCheckpointResponse with the given status.
func NewWriteBlockCheckpointResponse(success bool) *pb.WriteBlockCheckpointResponse {
	status := pb.WriteStatus_SUCCESS
	if !success {
		status = pb.WriteStatus_FAILED
	}

	return &pb.WriteBlockCheckpointResponse{
		Status: status,
	}
}

// NewReadBlockCheckpointResponse creates a ReadBlockCheckpointResponse with checkpoints.
func NewReadBlockCheckpointResponse(checkpoints []*pb.BlockCheckpoint) *pb.ReadBlockCheckpointResponse {
	return &pb.ReadBlockCheckpointResponse{
		Checkpoints: checkpoints,
	}
}

// FormatValidationError formats a validation error with context for user-friendly messages.
func FormatValidationError(field string, err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("validation failed for %s: %w", field, err)
}

// IsValidChainSelector checks if a chain selector is valid (greater than 0).
func IsValidChainSelector(chainSelector uint64) bool {
	return chainSelector > 0
}

// IsValidBlockHeight checks if a block height is valid (greater than 0).
func IsValidBlockHeight(blockHeight uint64) bool {
	return blockHeight > 0
}
