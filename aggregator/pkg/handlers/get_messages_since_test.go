package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func TestGetMessagesSinceHandler_Success_NoNextToken(t *testing.T) {
	t.Parallel()

	lggr := logger.TestSugared(t)
	store := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
	mon := aggregation_mocks.NewMockAggregatorMonitoring(t)
	labeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
	mon.EXPECT().Metrics().Return(labeler)

	const (
		sourceSel = uint64(1)
		destSel   = uint64(2)
	)
	participantID := "p1"
	signerAddr := addrSigner
	sourceVerifierAddr := addrSourceVerifier
	destVerifierAddr := addrDestVerifier
	committee := buildCommittee(sourceSel, destSel, sourceVerifierAddr, destVerifierAddr, []model.Signer{{ParticipantID: participantID, Addresses: []string{signerAddr}}})

	msg, _ := protocol.NewMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.Nonce(1), nil, nil, 0, 500_000, nil, nil, []byte{}, []byte{}, nil)
	msgID, _ := msg.MessageID()
	report := makeAggregatedReport(msgID[:], sourceSel, destSel, sourceVerifierAddr, signerAddr, participantID)

	store.EXPECT().QueryAggregatedReports(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&model.PaginatedAggregatedReports{Reports: []*model.CommitAggregatedReport{report}, NextPageToken: nil}, nil)
	labeler.EXPECT().RecordMessageSinceNumberOfRecordsReturned(mock.Anything, 1)

	h := NewGetMessagesSinceHandler(store, committee, lggr, mon)
	md := metadata.Pairs(model.CommitteeIDHeader, model.DefaultCommitteeID)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	resp, err := h.Handle(ctx, &pb.GetMessagesSinceRequest{SinceSequence: 0})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.Equal(t, int64(1), resp.Results[0].Sequence)
	// next token absent
	require.Empty(t, resp.NextToken)
}

func TestGetMessagesSinceHandler_Success_WithNextToken(t *testing.T) {
	t.Parallel()

	lggr := logger.TestSugared(t)
	store := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
	mon := aggregation_mocks.NewMockAggregatorMonitoring(t)
	labeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
	mon.EXPECT().Metrics().Return(labeler)

	participantID := "p1"
	signerAddr := addrSigner
	sourceVerifierAddr := addrSourceVerifier
	destVerifierAddr := addrDestVerifier
	committee := buildCommittee(1, 2, sourceVerifierAddr, destVerifierAddr, []model.Signer{{ParticipantID: participantID, Addresses: []string{signerAddr}}})

	msg, _ := protocol.NewMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.Nonce(1), nil, nil, 0, 500_000, nil, nil, []byte{}, []byte{}, nil)
	msgID, _ := msg.MessageID()
	report := makeAggregatedReport(msgID[:], 1, 2, sourceVerifierAddr, signerAddr, participantID)
	report.WrittenAt = time.Now()

	next := "nxt"
	store.EXPECT().QueryAggregatedReports(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&model.PaginatedAggregatedReports{Reports: []*model.CommitAggregatedReport{report}, NextPageToken: &next}, nil)
	labeler.EXPECT().RecordMessageSinceNumberOfRecordsReturned(mock.Anything, 1)

	h := NewGetMessagesSinceHandler(store, committee, lggr, mon)
	md := metadata.Pairs(model.CommitteeIDHeader, model.DefaultCommitteeID)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	resp, err := h.Handle(ctx, &pb.GetMessagesSinceRequest{SinceSequence: 0})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.Equal(t, "nxt", resp.NextToken)
}

func TestGetMessagesSinceHandler_StorageError(t *testing.T) {
	t.Parallel()

	lggr := logger.TestSugared(t)
	store := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
	mon := aggregation_mocks.NewMockAggregatorMonitoring(t)
	// no metrics expected on early error path

	h := NewGetMessagesSinceHandler(store, map[string]*model.Committee{}, lggr, mon)
	md := metadata.Pairs(model.CommitteeIDHeader, model.DefaultCommitteeID)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	store.EXPECT().QueryAggregatedReports(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, assertAnError())

	resp, err := h.Handle(ctx, &pb.GetMessagesSinceRequest{SinceSequence: 0})
	require.Error(t, err)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Nil(t, resp)
}
