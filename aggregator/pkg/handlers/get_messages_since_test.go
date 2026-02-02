package handlers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	msgdiscoverypb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-discovery/v1"
)

func TestGetMessagesSinceHandler_Success(t *testing.T) {
	t.Parallel()

	lggr := logger.TestSugared(t)
	store := mocks.NewMockCommitVerificationAggregatedStore(t)
	mon := mocks.NewMockAggregatorMonitoring(t)
	labeler := mocks.NewMockAggregatorMetricLabeler(t)
	mon.EXPECT().Metrics().Return(labeler)

	const (
		sourceSel = uint64(1)
		destSel   = uint64(2)
	)
	signerAddr := addrSigner
	destVerifierAddr := addrDestVerifier
	committee := buildCommittee(destSel, sourceSel, destVerifierAddr, []model.Signer{{Address: signerAddr}})

	msg := makeTestMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.SequenceNumber(1), []byte{})
	msgID, _ := msg.MessageID()
	report := makeAggregatedReport(msg, msgID[:], signerAddr)

	store.EXPECT().QueryAggregatedReports(mock.Anything, mock.Anything).Return(&model.AggregatedReportBatch{Reports: []*model.CommitAggregatedReport{report}, HasMore: false}, nil)
	labeler.EXPECT().RecordMessageSinceNumberOfRecordsReturned(mock.Anything, 1)

	h := NewGetMessagesSinceHandler(store, committee, lggr, mon)

	resp, err := h.Handle(context.Background(), &msgdiscoverypb.GetMessagesSinceRequest{SinceSequence: 0})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.Equal(t, int64(1), resp.Results[0].Sequence)
}

func TestGetMessagesSinceHandler_StorageError(t *testing.T) {
	t.Parallel()

	lggr := logger.TestSugared(t)
	store := mocks.NewMockCommitVerificationAggregatedStore(t)
	mon := mocks.NewMockAggregatorMonitoring(t)
	// no metrics expected on early error path

	h := NewGetMessagesSinceHandler(store, &model.Committee{}, lggr, mon)

	store.EXPECT().QueryAggregatedReports(mock.Anything, mock.Anything).Return(nil, assertAnError())

	resp, err := h.Handle(context.Background(), &msgdiscoverypb.GetMessagesSinceRequest{SinceSequence: 0})
	require.Error(t, err)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Nil(t, resp)
}

func TestGetMessagesSinceHandler_NegativeSequence(t *testing.T) {
	t.Parallel()

	lggr := logger.TestSugared(t)
	store := mocks.NewMockCommitVerificationAggregatedStore(t)
	mon := mocks.NewMockAggregatorMonitoring(t)

	h := NewGetMessagesSinceHandler(store, &model.Committee{}, lggr, mon)

	resp, err := h.Handle(context.Background(), &msgdiscoverypb.GetMessagesSinceRequest{SinceSequence: -1})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, err.Error(), "since_sequence cannot be negative")
	require.Nil(t, resp)
}

func TestGetMessagesSinceHandler_ContinuesOnMappingError(t *testing.T) {
	t.Parallel()

	lggr := logger.TestSugared(t)
	store := mocks.NewMockCommitVerificationAggregatedStore(t)
	mon := mocks.NewMockAggregatorMonitoring(t)
	labeler := mocks.NewMockAggregatorMetricLabeler(t)
	mon.EXPECT().Metrics().Return(labeler)

	const (
		sourceSel = uint64(1)
		destSel   = uint64(2)
	)
	signerAddr := addrSigner
	destVerifierAddr := addrDestVerifier
	committee := buildCommittee(destSel, sourceSel, destVerifierAddr, []model.Signer{{Address: signerAddr}})

	// Create three messages: valid, invalid (no verifications), and valid
	msg1 := makeTestMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.SequenceNumber(1), []byte{})
	msgID1, _ := msg1.MessageID()
	validReport1 := makeAggregatedReport(msg1, msgID1[:], signerAddr)
	validReport1.Sequence = 1

	msg2 := makeTestMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.SequenceNumber(2), []byte{})
	msgID2, _ := msg2.MessageID()
	invalidReport := &model.CommitAggregatedReport{
		MessageID:     msgID2[:],
		Verifications: []*model.CommitVerificationRecord{}, // Empty verifications cause mapping to fail
		Sequence:      2,
	}

	msg3 := makeTestMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.SequenceNumber(3), []byte{})
	msgID3, _ := msg3.MessageID()
	validReport2 := makeAggregatedReport(msg3, msgID3[:], signerAddr)
	validReport2.Sequence = 3

	store.EXPECT().QueryAggregatedReports(mock.Anything, mock.Anything).Return(
		&model.AggregatedReportBatch{
			Reports: []*model.CommitAggregatedReport{validReport1, invalidReport, validReport2},
			HasMore: false,
		}, nil)
	labeler.EXPECT().RecordMessageSinceNumberOfRecordsReturned(mock.Anything, 2)

	h := NewGetMessagesSinceHandler(store, committee, lggr, mon)

	resp, err := h.Handle(context.Background(), &msgdiscoverypb.GetMessagesSinceRequest{SinceSequence: 0})
	require.NoError(t, err)
	require.Len(t, resp.Results, 2, "should return only valid messages, skipping the invalid one")
	require.Equal(t, int64(1), resp.Results[0].Sequence)
	require.Equal(t, int64(3), resp.Results[1].Sequence)
}
