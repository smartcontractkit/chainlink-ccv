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
	_, err := h.Handle(context.Background(), &pb.BatchGetVerifierResultForMessageRequest{Requests: []*pb.GetVerifierResultForMessageRequest{}})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	// too many
	_, err = h.Handle(context.Background(), &pb.BatchGetVerifierResultForMessageRequest{Requests: []*pb.GetVerifierResultForMessageRequest{{}, {}, {}}})
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
	m1, _ := protocol.NewMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.Nonce(1), nil, nil, 0, 500_000, nil, nil, []byte{}, []byte{}, nil)
	m1ID, _ := m1.MessageID()
	m2, _ := protocol.NewMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.Nonce(2), nil, nil, 0, 500_000, nil, nil, []byte{0x1}, []byte{}, nil)
	m2ID, _ := m2.MessageID()

	participantID := "p1"
	signerAddr := addrSigner
	sourceVerifierAddr := addrSourceVerifier
	destVerifierAddr := addrDestVerifier
	committee := buildCommittee(sourceSel, destSel, sourceVerifierAddr, destVerifierAddr, []model.Signer{{ParticipantID: participantID, Addresses: []string{signerAddr}}})

	h := NewGetBatchCCVDataForMessageHandler(store, committee, 10, lggr)

	// create good report for m1, and mapping error for m2 by using wrong dest selector (no quorum config)
	report1 := makeAggregatedReport(m1ID[:], sourceSel, destSel, sourceVerifierAddr, signerAddr, participantID)
	report2 := makeAggregatedReport(m2ID[:], sourceSel, 99999 /* wrong dest selector */, sourceVerifierAddr, signerAddr, participantID)

	store.EXPECT().GetBatchCCVData(mock.Anything, mock.Anything).Return(map[string]*model.CommitAggregatedReport{
		common.Bytes2Hex(m1ID[:]): report1,
		common.Bytes2Hex(m2ID[:]): report2, // will map error
	}, nil)

	resp, err := h.Handle(context.Background(), &pb.BatchGetVerifierResultForMessageRequest{Requests: []*pb.GetVerifierResultForMessageRequest{
		{MessageId: m1ID[:]}, {MessageId: m2ID[:]}, {MessageId: []byte{0xFF}}, // missing
	}})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// first OK
	require.Equal(t, int32(codes.OK), resp.Errors[0].Code)
	require.Len(t, resp.Results, 1)
	// second mapping error
	require.Equal(t, int32(codes.Internal), resp.Errors[1].Code)
	// third not found
	require.Equal(t, int32(codes.NotFound), resp.Errors[2].Code)
}

func TestGetBatchCCVDataForMessageHandler_StorageError(t *testing.T) {
	t.Parallel()

	lggr := logger.TestSugared(t)
	store := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
	committee := &model.Committee{}
	h := NewGetBatchCCVDataForMessageHandler(store, committee, 10, lggr)

	store.EXPECT().GetBatchCCVData(mock.Anything, mock.Anything).Return(nil, status.Error(codes.Internal, "boom"))

	_, err := h.Handle(context.Background(), &pb.BatchGetVerifierResultForMessageRequest{Requests: []*pb.GetVerifierResultForMessageRequest{{MessageId: []byte{1}}}})
	require.Error(t, err)
	require.Equal(t, codes.Internal, status.Code(err))
}
