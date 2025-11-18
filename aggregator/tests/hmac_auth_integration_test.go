package tests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t,
		WithStorageType("memory"),
		WithoutClientAuth(),
	)
	require.NoError(t, err)
	defer cleanup()

	ctx := context.Background()

	// Test Aggregator service APIs
	t.Run("WriteChainStatus requires authentication", func(t *testing.T) {
		req := &pb.WriteChainStatusRequest{}

		_, err := aggregatorClient.WriteChainStatus(ctx, req)
		require.Error(t, err, "unauthenticated request should fail")

		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status error")
		require.Equal(t, codes.Unauthenticated, st.Code(), "should return Unauthenticated error")
	})

	t.Run("ReadChainStatus requires authentication", func(t *testing.T) {
		req := &pb.ReadChainStatusRequest{}

		_, err := aggregatorClient.ReadChainStatus(ctx, req)
		require.Error(t, err, "unauthenticated request should fail")

		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status error")
		require.Equal(t, codes.Unauthenticated, st.Code(), "should return Unauthenticated error")
	})

	t.Run("WriteCommitCCVNodeData requires authentication", func(t *testing.T) {
		req := &pb.WriteCommitteeVerifierNodeResultRequest{}

		_, err := aggregatorClient.WriteCommitteeVerifierNodeResult(ctx, req)
		require.Error(t, err, "unauthenticated request should fail")

		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status error")
		require.Equal(t, codes.Unauthenticated, st.Code(), "should return Unauthenticated error")
	})

	t.Run("ReadCommitCCVNodeData requires authentication", func(t *testing.T) {
		req := &pb.ReadCommitteeVerifierNodeResultRequest{}

		_, err := aggregatorClient.ReadCommitteeVerifierNodeResult(ctx, req)
		require.Error(t, err, "unauthenticated request should fail")

		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status error")
		require.Equal(t, codes.Unauthenticated, st.Code(), "should return Unauthenticated error")
	})

	// Test CCVData service APIs
	t.Run("GetVerifierResultForMessage supports an anonymous authentication", func(t *testing.T) {
		req := &pb.GetVerifierResultForMessageRequest{}

		_, err := ccvDataClient.GetVerifierResultForMessage(ctx, req)
		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status error")
		require.Equal(t, codes.NotFound, st.Code(), "should return NotFound error")
	})

	t.Run("GetMessagesSince supports an anonymous authentication", func(t *testing.T) {
		req := &pb.GetMessagesSinceRequest{}

		_, err := ccvDataClient.GetMessagesSince(ctx, req)
		require.NoError(t, err, "anonymous request should succeed")
	})
}
