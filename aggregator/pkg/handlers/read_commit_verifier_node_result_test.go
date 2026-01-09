package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

func TestReadCommitCCVNodeDataHandler_InvalidRequest_ReturnsInvalidArgument(t *testing.T) {
	t.Parallel()
	lggr := logger.TestSugared(t)
	store := mocks.NewMockCommitVerificationStore(t)
	h := NewReadCommitVerifierNodeResultHandler(store, lggr)

	resp, err := h.Handle(context.Background(), &committeepb.ReadCommitteeVerifierNodeResultRequest{MessageId: []byte{0x1}}) // too short
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.NotNil(t, resp)
}

func TestReadCommitCCVNodeDataHandler_StorageError_Propagates(t *testing.T) {
	t.Parallel()
	lggr := logger.TestSugared(t)
	store := mocks.NewMockCommitVerificationStore(t)
	h := NewReadCommitVerifierNodeResultHandler(store, lggr)
	msgID := make([]byte, 32)

	store.EXPECT().GetCommitVerification(mock.Anything, mock.Anything).Return(nil, status.Error(codes.Internal, "boom"))
	resp, err := h.Handle(context.Background(), &committeepb.ReadCommitteeVerifierNodeResultRequest{MessageId: msgID, Address: []byte{0xAA}})
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestReadCommitCCVNodeDataHandler_Success_MapsToProto(t *testing.T) {
	t.Parallel()
	lggr := logger.TestSugared(t)
	store := mocks.NewMockCommitVerificationStore(t)
	h := NewReadCommitVerifierNodeResultHandler(store, lggr)
	msgID := make([]byte, 32)

	rec := &model.CommitVerificationRecord{
		MessageID:  msgID,
		CCVVersion: []byte{0x1},
		Signature:  []byte{0x2},
		SignerIdentifier: &model.SignerIdentifier{
			Identifier: []byte{0xAA},
		},
	}
	rec.SetTimestampFromMillis(time.Now().UnixMilli())
	store.EXPECT().GetCommitVerification(mock.Anything, mock.Anything).Return(rec, nil)

	resp, err := h.Handle(context.Background(), &committeepb.ReadCommitteeVerifierNodeResultRequest{MessageId: msgID, Address: []byte{0xAA}})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.CommitteeVerifierNodeResult)
	require.Equal(t, []byte{0x1}, resp.CommitteeVerifierNodeResult.CcvVersion)
}
