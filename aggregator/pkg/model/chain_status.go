package model

import (
	"errors"
	"fmt"
	"strings"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// ValidateChainStatus validates a single chain status.
func ValidateChainStatus(chainStatus *pb.ChainStatus) error {
	if chainStatus == nil {
		return errors.New("chain status cannot be nil")
	}

	if chainStatus.ChainSelector == 0 {
		return errors.New("chain_selector must be greater than 0")
	}

	if chainStatus.FinalizedBlockHeight == 0 {
		return errors.New("finalized_block_height must be greater than 0")
	}

	// The disabled field is optional and doesn't require validation

	return nil
}

// ValidateWriteChainStatusRequest validates the WriteChainStatusRequest.
func ValidateWriteChainStatusRequest(req *pb.WriteChainStatusRequest) error {
	if req == nil {
		return errors.New("request cannot be nil")
	}

	if len(req.Statuses) == 0 {
		return errors.New("at least one chain status required")
	}

	if len(req.Statuses) > 1000 {
		return errors.New("maximum 1000 chain statuses per request")
	}

	// Validate each chain status in the request
	for i, chainStatus := range req.Statuses {
		if err := ValidateChainStatus(chainStatus); err != nil {
			return fmt.Errorf("chain_status[%d]: %w", i, err)
		}
	}

	return nil
}

// ValidateReadChainStatusRequest validates the ReadChainStatusRequest.
func ValidateReadChainStatusRequest(req *pb.ReadChainStatusRequest) error {
	if req == nil {
		return errors.New("request cannot be nil")
	}

	// ReadChainStatus has no additional validation requirements beyond authentication
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

// ProtoChainStatusToMap converts protobuf chain statuses to a map for storage.
// Disabled chains are excluded from the storage map.
func ProtoChainStatusToMap(protoChainStatuses []*pb.ChainStatus) map[uint64]uint64 {
	result := make(map[uint64]uint64)

	for _, chainStatus := range protoChainStatuses {
		if chainStatus != nil && !chainStatus.Disabled {
			result[chainStatus.ChainSelector] = chainStatus.FinalizedBlockHeight
		}
	}

	return result
}

// MapToProtoChainStatus converts a storage map to protobuf chain statuses.
// Results are sorted by chain_selector for deterministic ordering.
// All returned chain statuses have disabled=false since disabled chains are not stored.
func MapToProtoChainStatus(checkpoints map[uint64]uint64) []*pb.ChainStatus {
	result := make([]*pb.ChainStatus, 0, len(checkpoints))

	for chainSelector, blockHeight := range checkpoints {
		result = append(result, &pb.ChainStatus{
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: blockHeight,
			Disabled:             false, // Stored chains are always enabled
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

// NewWriteChainStatusResponse creates a WriteChainStatusResponse with the given status.
func NewWriteChainStatusResponse(success bool) *pb.WriteChainStatusResponse {
	status := pb.WriteStatus_SUCCESS
	if !success {
		status = pb.WriteStatus_FAILED
	}

	return &pb.WriteChainStatusResponse{
		Status: status,
	}
}

// NewReadChainStatusResponse creates a ReadChainStatusResponse with chain statuses.
func NewReadChainStatusResponse(chainStatuses []*pb.ChainStatus) *pb.ReadChainStatusResponse {
	return &pb.ReadChainStatusResponse{
		Statuses: chainStatuses,
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
