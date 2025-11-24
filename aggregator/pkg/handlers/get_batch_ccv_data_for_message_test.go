package handlers

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func TestGetBatchCCVDataForMessageHandler_ValidationErrors(t *testing.T) {
	t.Parallel()

	lggr := logger.TestSugared(t)
	store := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
	committee := &model.Committee{}

	h := NewGetBatchCCVDataForMessageHandler(store, committee, 2, lggr)

	// empty
	_, err := h.Handle(context.Background(), &pb.GetVerifierResultsForMessageRequest{MessageIds: [][]byte{}})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	// too many
	_, err = h.Handle(context.Background(), &pb.GetVerifierResultsForMessageRequest{MessageIds: [][]byte{{}, {}, {}}})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetBatchCCVDataForMessageHandler_MixedResults(t *testing.T) {
	t.Parallel()

	lggr := logger.TestSugared(t)
	store := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)

	const (
		sourceSel = uint64(1)
		destSel   = uint64(2)
	)
	// two messages
	m1 := makeTestMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.SequenceNumber(1), []byte{})
	m1ID, _ := m1.MessageID()
	m2 := makeTestMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.SequenceNumber(2), []byte{0x1})
	m2ID, _ := m2.MessageID()

	signerAddr := addrSigner
	destVerifierAddr := addrDestVerifier
	committee := buildCommittee(destSel, sourceSel, destVerifierAddr, []model.Signer{{Address: signerAddr}})

	h := NewGetBatchCCVDataForMessageHandler(store, committee, 10, lggr)

	// For report2, we need a message with destSel=99999 to trigger the mapping error
	// The original message has destSel=2, so create a different message for report2
	m2WithWrongDest := makeTestMessage(protocol.ChainSelector(sourceSel), protocol.ChainSelector(99999), protocol.SequenceNumber(2), []byte{0x1})

	report1 := makeAggregatedReport(m1, m1ID[:], signerAddr)
	report2 := makeAggregatedReport(m2WithWrongDest, m2ID[:], signerAddr)

	store.EXPECT().GetBatchCCVData(mock.Anything, mock.Anything).Return(map[string]*model.CommitAggregatedReport{
		common.Bytes2Hex(m1ID[:]): report1,
		common.Bytes2Hex(m2ID[:]): report2, // will map error
	}, nil)

	resp, err := h.Handle(context.Background(), &pb.GetVerifierResultsForMessageRequest{MessageIds: [][]byte{
		m1ID[:], m2ID[:], {0xFF}, // missing
	}})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify 1:1 correspondence with 3 input message IDs
	require.Len(t, resp.Results, 3, "should have exactly 3 result entries")
	require.Len(t, resp.Errors, 3, "should have exactly 3 error entries")

	// first OK
	require.Equal(t, int32(codes.OK), resp.Errors[0].Code)
	require.NotNil(t, resp.Results[0], "first result should not be nil")
	// second mapping error
	require.Equal(t, int32(codes.Internal), resp.Errors[1].Code)
	require.Nil(t, resp.Results[1], "second result should be nil due to mapping error")
	// third not found
	require.Equal(t, int32(codes.NotFound), resp.Errors[2].Code)
	require.Nil(t, resp.Results[2], "third result should be nil for not-found message")
}

func TestGetBatchCCVDataForMessageHandler_StorageError(t *testing.T) {
	t.Parallel()

	lggr := logger.TestSugared(t)
	store := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
	committee := &model.Committee{}
	h := NewGetBatchCCVDataForMessageHandler(store, committee, 10, lggr)

	store.EXPECT().GetBatchCCVData(mock.Anything, mock.Anything).Return(nil, status.Error(codes.Internal, "boom"))

	_, err := h.Handle(context.Background(), &pb.GetVerifierResultsForMessageRequest{MessageIds: [][]byte{{1}}})
	require.Error(t, err)
	require.Equal(t, codes.Internal, status.Code(err))
}
