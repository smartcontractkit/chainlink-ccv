package model

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

// TestBlockCheckpointValidation tests validation of BlockCheckpoint.
func TestBlockCheckpointValidation(t *testing.T) {
	t.Run("valid_checkpoint_passes", func(t *testing.T) {
		checkpoint := &aggregator.BlockCheckpoint{
			ChainSelector:        1,
			FinalizedBlockHeight: 100,
		}

		err := ValidateBlockCheckpoint(checkpoint)
		require.NoError(t, err, "valid checkpoint should pass validation")
	})

	t.Run("zero_chain_selector_fails", func(t *testing.T) {
		checkpoint := &aggregator.BlockCheckpoint{
			ChainSelector:        0,
			FinalizedBlockHeight: 100,
		}

		err := ValidateBlockCheckpoint(checkpoint)
		require.Error(t, err, "zero chain selector should fail validation")
		require.Contains(t, err.Error(), "chain_selector must be greater than 0")
	})

	t.Run("zero_block_height_fails", func(t *testing.T) {
		checkpoint := &aggregator.BlockCheckpoint{
			ChainSelector:        1,
			FinalizedBlockHeight: 0,
		}

		err := ValidateBlockCheckpoint(checkpoint)
		require.Error(t, err, "zero block height should fail validation")
		require.Contains(t, err.Error(), "finalized_block_height must be greater than 0")
	})

	t.Run("nil_checkpoint_fails", func(t *testing.T) {
		err := ValidateBlockCheckpoint(nil)
		require.Error(t, err, "nil checkpoint should fail validation")
		require.Contains(t, err.Error(), "checkpoint cannot be nil")
	})
}

// TestWriteBlockCheckpointRequestValidation tests validation of write requests.
func TestWriteBlockCheckpointRequestValidation(t *testing.T) {
	t.Run("valid_request_passes", func(t *testing.T) {
		req := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 100},
				{ChainSelector: 2, FinalizedBlockHeight: 200},
			},
		}

		err := ValidateWriteBlockCheckpointRequest(req)
		require.NoError(t, err, "valid request should pass validation")
	})

	t.Run("empty_checkpoints_fails", func(t *testing.T) {
		req := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{},
		}

		err := ValidateWriteBlockCheckpointRequest(req)
		require.Error(t, err, "empty checkpoints should fail validation")
		require.Contains(t, err.Error(), "at least one checkpoint required")
	})

	t.Run("nil_checkpoints_fails", func(t *testing.T) {
		req := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: nil,
		}

		err := ValidateWriteBlockCheckpointRequest(req)
		require.Error(t, err, "nil checkpoints should fail validation")
		require.Contains(t, err.Error(), "at least one checkpoint required")
	})

	t.Run("nil_request_fails", func(t *testing.T) {
		err := ValidateWriteBlockCheckpointRequest(nil)
		require.Error(t, err, "nil request should fail validation")
		require.Contains(t, err.Error(), "request cannot be nil")
	})

	t.Run("too_many_checkpoints_fails", func(t *testing.T) {
		// Create more than 1000 checkpoints
		checkpoints := make([]*aggregator.BlockCheckpoint, 1001)
		for i := 0; i < 1001; i++ {
			checkpoints[i] = &aggregator.BlockCheckpoint{
				ChainSelector:        uint64(i + 1),
				FinalizedBlockHeight: 100,
			}
		}

		req := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: checkpoints,
		}

		err := ValidateWriteBlockCheckpointRequest(req)
		require.Error(t, err, "too many checkpoints should fail validation")
		require.Contains(t, err.Error(), "maximum 1000 checkpoints per request")
	})

	t.Run("invalid_checkpoint_in_request_fails", func(t *testing.T) {
		req := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 100},
				{ChainSelector: 0, FinalizedBlockHeight: 200}, // Invalid
			},
		}

		err := ValidateWriteBlockCheckpointRequest(req)
		require.Error(t, err, "request with invalid checkpoint should fail")
		require.Contains(t, err.Error(), "chain_selector must be greater than 0")
	})
}

// TestAPIKeyValidation tests API key validation.
func TestAPIKeyValidation(t *testing.T) {
	t.Run("valid_api_key_passes", func(t *testing.T) {
		err := ValidateAPIKey("valid-api-key")
		require.NoError(t, err, "valid API key should pass validation")
	})

	t.Run("empty_api_key_fails", func(t *testing.T) {
		err := ValidateAPIKey("")
		require.Error(t, err, "empty API key should fail validation")
		require.Contains(t, err.Error(), "api key cannot be empty")
	})

	t.Run("whitespace_only_api_key_fails", func(t *testing.T) {
		err := ValidateAPIKey("   ")
		require.Error(t, err, "whitespace-only API key should fail validation")
		require.Contains(t, err.Error(), "api key cannot be empty")
	})

	t.Run("very_long_api_key_fails", func(t *testing.T) {
		longKey := make([]byte, 1001)
		for i := range longKey {
			longKey[i] = 'a'
		}

		err := ValidateAPIKey(string(longKey))
		require.Error(t, err, "very long API key should fail validation")
		require.Contains(t, err.Error(), "api key too long")
	})
}

// TestCheckpointConversion tests conversion between proto and internal models.
func TestCheckpointConversion(t *testing.T) {
	t.Run("proto_to_map_conversion", func(t *testing.T) {
		checkpoints := []*aggregator.BlockCheckpoint{
			{ChainSelector: 1, FinalizedBlockHeight: 100},
			{ChainSelector: 2, FinalizedBlockHeight: 200},
			{ChainSelector: 5, FinalizedBlockHeight: 500},
		}

		result := ProtoCheckpointsToMap(checkpoints)

		expected := map[uint64]uint64{
			1: 100,
			2: 200,
			5: 500,
		}

		require.Equal(t, expected, result, "conversion should create correct map")
	})

	t.Run("map_to_proto_conversion", func(t *testing.T) {
		checkpointMap := map[uint64]uint64{
			1: 100,
			2: 200,
			5: 500,
		}

		result := MapToProtoCheckpoints(checkpointMap)

		require.Len(t, result, 3, "should convert all checkpoints")

		// Convert back to map for comparison (order may vary)
		resultMap := make(map[uint64]uint64)
		for _, cp := range result {
			resultMap[cp.ChainSelector] = cp.FinalizedBlockHeight
		}

		require.Equal(t, checkpointMap, resultMap, "round-trip conversion should preserve data")
	})

	t.Run("empty_map_conversion", func(t *testing.T) {
		result := MapToProtoCheckpoints(map[uint64]uint64{})
		require.Empty(t, result, "empty map should convert to empty slice")
	})

	t.Run("nil_checkpoints_conversion", func(t *testing.T) {
		result := ProtoCheckpointsToMap(nil)
		require.Empty(t, result, "nil checkpoints should convert to empty map")
	})
}

// TestDuplicateHandling tests handling of duplicate chain selectors.
func TestDuplicateHandling(t *testing.T) {
	t.Run("duplicate_chain_selectors_in_request", func(t *testing.T) {
		checkpoints := []*aggregator.BlockCheckpoint{
			{ChainSelector: 1, FinalizedBlockHeight: 100},
			{ChainSelector: 2, FinalizedBlockHeight: 200},
			{ChainSelector: 1, FinalizedBlockHeight: 150}, // Duplicate chain selector
		}

		result := ProtoCheckpointsToMap(checkpoints)

		// Later entry should override earlier one
		require.Equal(t, uint64(150), result[1], "later checkpoint should override earlier")
		require.Equal(t, uint64(200), result[2], "other checkpoints should remain unchanged")
		require.Len(t, result, 2, "should have correct number of unique chains")
	})

	t.Run("validate_allows_duplicates_in_request", func(t *testing.T) {
		req := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 100},
				{ChainSelector: 1, FinalizedBlockHeight: 150}, // Duplicate
			},
		}

		err := ValidateWriteBlockCheckpointRequest(req)
		require.NoError(t, err, "duplicates within request should be allowed")
	})
}
