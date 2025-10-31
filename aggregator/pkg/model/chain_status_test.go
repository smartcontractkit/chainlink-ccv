package model

import (
	"testing"

	"github.com/stretchr/testify/require"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// TestChainStatusValidation tests validation of ChainStatus.
func TestChainStatusValidation(t *testing.T) {
	t.Run("valid_chain_status_passes", func(t *testing.T) {
		chainStatus := &pb.ChainStatus{
			ChainSelector:        1,
			FinalizedBlockHeight: 100,
		}

		err := ValidateChainStatus(chainStatus)
		require.NoError(t, err, "valid chain status should pass validation")
	})

	t.Run("zero_chain_selector_fails", func(t *testing.T) {
		chainStatus := &pb.ChainStatus{
			ChainSelector:        0,
			FinalizedBlockHeight: 100,
		}

		err := ValidateChainStatus(chainStatus)
		require.Error(t, err, "zero chain selector should fail validation")
		require.Contains(t, err.Error(), "chain_selector must be greater than 0")
	})

	t.Run("zero_block_height_fails", func(t *testing.T) {
		chainStatus := &pb.ChainStatus{
			ChainSelector:        1,
			FinalizedBlockHeight: 0,
		}

		err := ValidateChainStatus(chainStatus)
		require.Error(t, err, "zero block height should fail validation")
		require.Contains(t, err.Error(), "finalized_block_height must be greater than 0")
	})

	t.Run("nil_chain_status_fails", func(t *testing.T) {
		err := ValidateChainStatus(nil)
		require.Error(t, err, "nil chain status should fail validation")
		require.Contains(t, err.Error(), "chain status cannot be nil")
	})
}

// TestWriteChainStatusRequestValidation tests validation of write requests.
func TestWriteChainStatusRequestValidation(t *testing.T) {
	t.Run("valid_request_passes", func(t *testing.T) {
		req := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 100, Disabled: false},
				{ChainSelector: 2, FinalizedBlockHeight: 200, Disabled: false},
			},
		}

		err := ValidateWriteChainStatusRequest(req)
		require.NoError(t, err, "valid request should pass validation")
	})

	t.Run("empty_chain_statuses_fails", func(t *testing.T) {
		req := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{},
		}

		err := ValidateWriteChainStatusRequest(req)
		require.Error(t, err, "empty chain statuses should fail validation")
		require.Contains(t, err.Error(), "at least one chain status required")
	})

	t.Run("nil_chain_statuses_fails", func(t *testing.T) {
		req := &pb.WriteChainStatusRequest{
			Statuses: nil,
		}

		err := ValidateWriteChainStatusRequest(req)
		require.Error(t, err, "nil chain statuses should fail validation")
		require.Contains(t, err.Error(), "at least one chain status required")
	})

	t.Run("nil_request_fails", func(t *testing.T) {
		err := ValidateWriteChainStatusRequest(nil)
		require.Error(t, err, "nil request should fail validation")
		require.Contains(t, err.Error(), "request cannot be nil")
	})

	t.Run("too_many_chain_statuses_fails", func(t *testing.T) {
		// Create more than 1000 chain statuses
		chainStatuses := make([]*pb.ChainStatus, 1001)
		for i := 0; i < 1001; i++ {
			chainStatuses[i] = &pb.ChainStatus{
				ChainSelector:        uint64(i + 1),
				FinalizedBlockHeight: 100,
			}
		}

		req := &pb.WriteChainStatusRequest{
			Statuses: chainStatuses,
		}

		err := ValidateWriteChainStatusRequest(req)
		require.Error(t, err, "too many chain statuses should fail validation")
		require.Contains(t, err.Error(), "maximum 1000 chain statuses per request")
	})

	t.Run("invalid_chain_status_in_request_fails", func(t *testing.T) {
		req := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 100, Disabled: false},
				{ChainSelector: 0, FinalizedBlockHeight: 200, Disabled: false}, // Invalid
			},
		}

		err := ValidateWriteChainStatusRequest(req)
		require.Error(t, err, "request with invalid chain status should fail")
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
