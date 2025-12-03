package handlers

import (
	"context"
	"testing"

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

func TestGetMessagesSinceHandler_Success(t *testing.T) {
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
	signerAddr := addrSigner
	destVerifierAddr := addrDestVerifier
	committee := buildCommittee(destSel, sourceSel, destVerifierAddr, []model.Signer{{Address: signerAddr}})

	msg := makeTestMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.SequenceNumber(1), []byte{})
	msgID, _ := msg.MessageID()
	report := makeAggregatedReport(msg, msgID[:], signerAddr)

	store.EXPECT().QueryAggregatedReports(mock.Anything, mock.Anything).Return(&model.AggregatedReportBatch{Reports: []*model.CommitAggregatedReport{report}, HasMore: false}, nil)
	labeler.EXPECT().RecordMessageSinceNumberOfRecordsReturned(mock.Anything, 1)

	h := NewGetMessagesSinceHandler(store, committee, lggr, mon)

	resp, err := h.Handle(context.Background(), &pb.GetMessagesSinceRequest{SinceSequence: 0})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.Equal(t, int64(1), resp.Results[0].Sequence)
}

func TestGetMessagesSinceHandler_StorageError(t *testing.T) {
	t.Parallel()

	lggr := logger.TestSugared(t)
	store := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
	mon := aggregation_mocks.NewMockAggregatorMonitoring(t)
	// no metrics expected on early error path

	h := NewGetMessagesSinceHandler(store, &model.Committee{}, lggr, mon)

	store.EXPECT().QueryAggregatedReports(mock.Anything, mock.Anything).Return(nil, assertAnError())

	resp, err := h.Handle(context.Background(), &pb.GetMessagesSinceRequest{SinceSequence: 0})
	require.Error(t, err)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Nil(t, resp)
}
