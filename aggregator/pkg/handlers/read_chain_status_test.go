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

func TestReadChainStatusHandler_Unauthenticated_ReturnsUnauthenticated(t *testing.T) {
	t.Parallel()
	s := aggregation_mocks.NewMockChainStatusStorageInterface(t)
	h := NewReadChainStatusHandler(s, logger.TestSugared(t))

	resp, err := h.Handle(context.Background(), &pb.ReadChainStatusRequest{})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestReadChainStatusHandler_NilRequest_ReturnsInvalidArgument(t *testing.T) {
	t.Parallel()
	s := aggregation_mocks.NewMockChainStatusStorageInterface(t)
	h := NewReadChainStatusHandler(s, logger.TestSugared(t))
	ctx := auth.ToContext(context.Background(), auth.CreateCallerIdentity("clientA", false))

	resp, err := h.Handle(ctx, nil)
	require.Error(t, err)
	require.Nil(t, resp)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestReadChainStatusHandler_StorageError_ReturnsInternal(t *testing.T) {
	t.Parallel()
	s := aggregation_mocks.NewMockChainStatusStorageInterface(t)
	h := NewReadChainStatusHandler(s, logger.TestSugared(t))
	ctx := auth.ToContext(context.Background(), auth.CreateCallerIdentity("clientA", false))

	s.EXPECT().GetClientChainStatus(mock.Anything, "clientA").Return(nil, status.Error(codes.Internal, "boom"))

	resp, err := h.Handle(ctx, &pb.ReadChainStatusRequest{})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Equal(t, codes.Internal, status.Code(err))
}

func TestReadChainStatusHandler_Success_MapsToProto(t *testing.T) {
	t.Parallel()
	s := aggregation_mocks.NewMockChainStatusStorageInterface(t)
	h := NewReadChainStatusHandler(s, logger.TestSugared(t))
	ctx := auth.ToContext(context.Background(), auth.CreateCallerIdentity("clientA", false))

	data := map[uint64]*common.ChainStatus{
		1: {FinalizedBlockHeight: 100, Disabled: false},
		2: {FinalizedBlockHeight: 200, Disabled: true},
	}
	s.EXPECT().GetClientChainStatus(mock.Anything, "clientA").Return(data, nil)

	resp, err := h.Handle(ctx, &pb.ReadChainStatusRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Statuses, 2)
	// order is not guaranteed; check by map
	found := map[uint64]bool{}
	for _, st := range resp.Statuses {
		if st.ChainSelector == 1 && st.FinalizedBlockHeight == 100 && !st.Disabled {
			found[1] = true
		}
		if st.ChainSelector == 2 && st.FinalizedBlockHeight == 200 && st.Disabled {
			found[2] = true
		}
	}
	require.True(t, found[1] && found[2])
}
