package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func TestBatchWriteCommitCCVNodeDataHandler_MixedSuccessAndInvalidArgument(t *testing.T) {
	t.Parallel()

	// Common test scaffolding
	lggr := logger.TestSugared(t)
	store := aggregation_mocks.NewMockCommitVerificationStore(t)
	agg := aggregation_mocks.NewMockAggregationTriggerer(t)

	signer := &model.IdentifierSigner{
		ParticipantID: "p1",
		Address:       []byte{0xAA},
	}
	sig := aggregation_mocks.NewMockSignatureValidator(t)
	sig.EXPECT().ValidateSignature(mock.Anything, mock.Anything).Return([]*model.IdentifierSigner{signer}, nil, nil)
	sig.EXPECT().DeriveAggregationKey(mock.Anything, mock.Anything).Return("messageId", nil)

	// Aggregation may be called once for the valid request
	agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything).Return(nil).Maybe()

	// For the valid request, expect one store call
	store.EXPECT().SaveCommitVerification(mock.Anything, mock.Anything, mock.Anything).Return(nil)

	writeHandler := NewWriteCommitCCVNodeDataHandler(store, agg, lggr, sig)
	batchHandler := NewBatchWriteCommitCCVNodeDataHandler(writeHandler)

	// Build requests
	validMsgID := make([]byte, 32)
	for i := range validMsgID {
		validMsgID[i] = 0x11
	}
	_ = time.Now().UnixMilli()

	validUUID := "550e8400-e29b-41d4-a716-4466554400aa"
	validReq := makeValidProtoRequest(validUUID)

	// Invalid idempotency key should return InvalidArgument from inner handler
	invalidReq := makeValidProtoRequest("not-a-uuid")

	resp, err := batchHandler.Handle(context.Background(), &pb.BatchWriteCommitCCVNodeDataRequest{
		Requests: []*pb.WriteCommitCCVNodeDataRequest{validReq, invalidReq},
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Responses, 2)
	require.Len(t, resp.Errors, 2)

	// First should succeed
	require.Equal(t, pb.WriteStatus_SUCCESS, resp.Responses[0].Status)
	require.NotNil(t, resp.Errors[0])
	require.Equal(t, int32(codes.OK), resp.Errors[0].Code)

	// Second should fail with InvalidArgument
	require.Equal(t, pb.WriteStatus_FAILED, resp.Responses[1].Status)
	require.NotNil(t, resp.Errors[1])
	require.Equal(t, int32(codes.InvalidArgument), resp.Errors[1].Code)
}
