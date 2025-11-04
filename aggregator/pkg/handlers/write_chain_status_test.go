package handlers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func TestWriteChainStatusHandler_Unauthenticated_ReturnsUnauthenticated(t *testing.T) {
	t.Parallel()
	s := aggregation_mocks.NewMockChainStatusStorageInterface(t)
	h := NewWriteChainStatusHandler(s, logger.TestSugared(t))

	resp, err := h.Handle(context.Background(), &pb.WriteChainStatusRequest{})
	require.Error(t, err)
	require.Equal(t, pb.WriteStatus_FAILED, resp.Status)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestWriteChainStatusHandler_InvalidRequest_ReturnsInvalidArgument(t *testing.T) {
	t.Parallel()
	s := aggregation_mocks.NewMockChainStatusStorageInterface(t)
	h := NewWriteChainStatusHandler(s, logger.TestSugared(t))
	ctx := auth.ToContext(context.Background(), auth.CreateCallerIdentity("clientA", false))

	resp, err := h.Handle(ctx, &pb.WriteChainStatusRequest{Statuses: nil})
	require.Error(t, err)
	require.Equal(t, pb.WriteStatus_FAILED, resp.Status)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestWriteChainStatusHandler_StorageError_ReturnsInternal(t *testing.T) {
	t.Parallel()
	s := aggregation_mocks.NewMockChainStatusStorageInterface(t)
	h := NewWriteChainStatusHandler(s, logger.TestSugared(t))
	ctx := auth.ToContext(context.Background(), auth.CreateCallerIdentity("clientA", false))

	statuses := []*pb.ChainStatus{{ChainSelector: 1, FinalizedBlockHeight: 100}}
	s.EXPECT().StoreChainStatus(mock.Anything, "clientA", mock.Anything).Return(status.Error(codes.Internal, "boom"))

	resp, err := h.Handle(ctx, &pb.WriteChainStatusRequest{Statuses: statuses})
	require.Error(t, err)
	require.Equal(t, pb.WriteStatus_FAILED, resp.Status)
	require.Equal(t, codes.Internal, status.Code(err))
}

func TestWriteChainStatusHandler_Success_ReturnsSuccess(t *testing.T) {
	t.Parallel()
	s := aggregation_mocks.NewMockChainStatusStorageInterface(t)
	h := NewWriteChainStatusHandler(s, logger.TestSugared(t))
	ctx := auth.ToContext(context.Background(), auth.CreateCallerIdentity("clientA", false))

	statuses := []*pb.ChainStatus{{ChainSelector: 1, FinalizedBlockHeight: 100, Disabled: false}}
	s.EXPECT().StoreChainStatus(mock.Anything, "clientA", mock.MatchedBy(func(m map[uint64]*common.ChainStatus) bool {
		cs, ok := m[1]
		return ok && cs.FinalizedBlockHeight == 100 && !cs.Disabled
	})).Return(nil)

	resp, err := h.Handle(ctx, &pb.WriteChainStatusRequest{Statuses: statuses})
	require.NoError(t, err)
	require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)
}
