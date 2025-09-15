// Package tests contains functional tests for the aggregator service.
package tests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

// TestWriteBlockCheckpointContract tests the WriteBlockCheckpoint gRPC contract.
func TestWriteBlockCheckpointContract(t *testing.T) {
	// This test will fail until implementation is complete
	// Following RED-GREEN-REFACTOR: Write failing test first

	t.Run("valid_request_returns_success", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := contextWithAPIKey("test-client-1")

		req := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 100},
				{ChainSelector: 2, FinalizedBlockHeight: 200},
			},
		}

		// Execute
		resp, err := client.WriteBlockCheckpoint(ctx, req)

		// Verify contract compliance
		require.NoError(t, err, "valid request should not return error")
		require.NotNil(t, resp, "response should not be nil")
		require.Equal(t, aggregator.WriteStatus_SUCCESS, resp.Status, "status should be SUCCESS")
	})

	t.Run("missing_api_key_returns_unauthenticated", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := context.Background() // No API key

		req := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 100},
			},
		}

		// Execute
		_, err = client.WriteBlockCheckpoint(ctx, req)

		// Verify contract compliance
		require.Error(t, err, "missing api key should return error")
		st := status.Convert(err)
		require.Equal(t, codes.Unauthenticated, st.Code(), "should return Unauthenticated")
		require.Contains(t, st.Message(), "api key required", "error message should mention api key")
	})

	t.Run("empty_api_key_returns_unauthenticated", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := contextWithAPIKey("")

		req := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 100},
			},
		}

		// Execute
		_, err = client.WriteBlockCheckpoint(ctx, req)

		// Verify contract compliance
		require.Error(t, err, "empty api key should return error")
		st := status.Convert(err)
		require.Equal(t, codes.Unauthenticated, st.Code(), "should return Unauthenticated")
		require.Contains(t, st.Message(), "api key cannot be empty", "error message should mention empty api key")
	})

	t.Run("zero_chain_selector_returns_invalid_argument", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := contextWithAPIKey("test-client-1")

		req := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{
				{ChainSelector: 0, FinalizedBlockHeight: 100}, // Invalid
			},
		}

		// Execute
		_, err = client.WriteBlockCheckpoint(ctx, req)

		// Verify contract compliance
		require.Error(t, err, "zero chain_selector should return error")
		st := status.Convert(err)
		require.Equal(t, codes.InvalidArgument, st.Code(), "should return InvalidArgument")
		require.Contains(t, st.Message(), "chain_selector must be greater than 0", "error message should mention chain_selector")
	})

	t.Run("zero_block_height_returns_invalid_argument", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := contextWithAPIKey("test-client-1")

		req := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 0}, // Invalid
			},
		}

		// Execute
		_, err = client.WriteBlockCheckpoint(ctx, req)

		// Verify contract compliance
		require.Error(t, err, "zero finalized_block_height should return error")
		st := status.Convert(err)
		require.Equal(t, codes.InvalidArgument, st.Code(), "should return InvalidArgument")
		require.Contains(t, st.Message(), "finalized_block_height must be greater than 0", "error message should mention finalized_block_height")
	})

	t.Run("empty_checkpoints_returns_invalid_argument", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := contextWithAPIKey("test-client-1")

		req := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{}, // Empty
		}

		// Execute
		_, err = client.WriteBlockCheckpoint(ctx, req)

		// Verify contract compliance
		require.Error(t, err, "empty checkpoints should return error")
		st := status.Convert(err)
		require.Equal(t, codes.InvalidArgument, st.Code(), "should return InvalidArgument")
		require.Contains(t, st.Message(), "at least one checkpoint required", "error message should mention minimum requirement")
	})
}

// TestReadBlockCheckpointContract tests the ReadBlockCheckpoint gRPC contract.
func TestReadBlockCheckpointContract(t *testing.T) {
	// This test will fail until implementation is complete
	// Following RED-GREEN-REFACTOR: Write failing test first

	t.Run("valid_request_with_data_returns_checkpoints", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := contextWithAPIKey("test-client-1")

		// Pre-populate data
		writeReq := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 100},
				{ChainSelector: 2, FinalizedBlockHeight: 200},
			},
		}
		_, err = client.WriteBlockCheckpoint(ctx, writeReq)
		require.NoError(t, err, "setup write should succeed")

		// Execute
		resp, err := client.ReadBlockCheckpoint(ctx, &aggregator.ReadBlockCheckpointRequest{})

		// Verify contract compliance
		require.NoError(t, err, "valid request should not return error")
		require.NotNil(t, resp, "response should not be nil")
		require.Len(t, resp.Checkpoints, 2, "should return 2 checkpoints")

		// Verify data integrity
		checkpoints := resp.Checkpoints
		require.Equal(t, uint64(1), checkpoints[0].ChainSelector)
		require.Equal(t, uint64(100), checkpoints[0].FinalizedBlockHeight)
		require.Equal(t, uint64(2), checkpoints[1].ChainSelector)
		require.Equal(t, uint64(200), checkpoints[1].FinalizedBlockHeight)
	})

	t.Run("valid_request_no_data_returns_empty_array", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := contextWithAPIKey("new-client-no-data")

		// Execute
		resp, err := client.ReadBlockCheckpoint(ctx, &aggregator.ReadBlockCheckpointRequest{})

		// Verify contract compliance
		require.NoError(t, err, "request with no data should not return error")
		require.NotNil(t, resp, "response should not be nil")
		require.Empty(t, resp.Checkpoints, "should return empty array when no data")
	})

	t.Run("missing_api_key_returns_unauthenticated", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := context.Background() // No API key

		// Execute
		_, err = client.ReadBlockCheckpoint(ctx, &aggregator.ReadBlockCheckpointRequest{})

		// Verify contract compliance
		require.Error(t, err, "missing api key should return error")
		st := status.Convert(err)
		require.Equal(t, codes.Unauthenticated, st.Code(), "should return Unauthenticated")
		require.Contains(t, st.Message(), "api key required", "error message should mention api key")
	})

	t.Run("client_isolation_verified", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		client1Ctx := contextWithAPIKey("client-1")
		client2Ctx := contextWithAPIKey("client-2")

		// Client 1 writes data
		writeReq := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 100},
			},
		}
		_, err = client.WriteBlockCheckpoint(client1Ctx, writeReq)
		require.NoError(t, err, "client 1 write should succeed")

		// Client 2 reads (should get empty)
		resp2, err := client.ReadBlockCheckpoint(client2Ctx, &aggregator.ReadBlockCheckpointRequest{})
		require.NoError(t, err, "client 2 read should succeed")
		require.Empty(t, resp2.Checkpoints, "client 2 should not see client 1 data")

		// Client 1 reads (should get their data)
		resp1, err := client.ReadBlockCheckpoint(client1Ctx, &aggregator.ReadBlockCheckpointRequest{})
		require.NoError(t, err, "client 1 read should succeed")
		require.Len(t, resp1.Checkpoints, 1, "client 1 should see their data")
	})
}

// TestCheckpointOverrideContract tests the override behavior contract.
func TestCheckpointOverrideContract(t *testing.T) {
	t.Run("duplicate_chain_selector_overrides_previous", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := contextWithAPIKey("test-client-override")

		// Write initial data
		writeReq1 := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 100},
			},
		}
		_, err = client.WriteBlockCheckpoint(ctx, writeReq1)
		require.NoError(t, err, "initial write should succeed")

		// Override with new data for same chain
		writeReq2 := &aggregator.WriteBlockCheckpointRequest{
			Checkpoints: []*aggregator.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 200}, // Override
			},
		}
		_, err = client.WriteBlockCheckpoint(ctx, writeReq2)
		require.NoError(t, err, "override write should succeed")

		// Verify override worked
		resp, err := client.ReadBlockCheckpoint(ctx, &aggregator.ReadBlockCheckpointRequest{})
		require.NoError(t, err, "read should succeed")
		require.Len(t, resp.Checkpoints, 1, "should have 1 checkpoint")
		require.Equal(t, uint64(200), resp.Checkpoints[0].FinalizedBlockHeight, "should have new value")
	})
}

// Helper functions

func contextWithAPIKey(apiKey string) context.Context {
	md := metadata.New(map[string]string{"api-key": apiKey})
	return metadata.NewOutgoingContext(context.Background(), md)
}
