package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

func TestBatchWriteCommitCCVNodeDataHandler_BatchSizeValidation(t *testing.T) {
	t.Parallel()

	const testCallerID = "test-caller"

	tests := []struct {
		name           string
		numRequests    int
		maxBatchSize   int
		expectCode     codes.Code
		expectErrorMsg string
	}{
		{
			name:           "empty_requests_returns_invalid_argument",
			numRequests:    0,
			maxBatchSize:   10,
			expectCode:     codes.InvalidArgument,
			expectErrorMsg: "requests cannot be empty",
		},
		{
			name:           "exceeds_max_batch_size_returns_invalid_argument",
			numRequests:    5,
			maxBatchSize:   3,
			expectCode:     codes.InvalidArgument,
			expectErrorMsg: "too many requests: 5, maximum allowed: 3",
		},
		{
			name:         "at_max_batch_size_is_allowed",
			numRequests:  3,
			maxBatchSize: 3,
			expectCode:   codes.OK,
		},
		{
			name:         "below_max_batch_size_is_allowed",
			numRequests:  2,
			maxBatchSize: 5,
			expectCode:   codes.OK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lggr := logger.TestSugared(t)
			store := mocks.NewMockCommitVerificationStore(t)
			agg := mocks.NewMockAggregationTriggerer(t)
			sig := mocks.NewMockSignatureValidator(t)

			signer := &model.SignerIdentifier{Identifier: []byte{0xAA}}

			if tc.expectCode == codes.OK {
				sig.EXPECT().ValidateSignature(mock.Anything, mock.Anything).Return(&model.SignatureValidationResult{
					Signer: signer,
				}, nil).Maybe()
				sig.EXPECT().DeriveAggregationKey(mock.Anything, mock.Anything).Return("messageId", nil).Maybe()
				agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything, testCallerID, time.Millisecond).Return(nil).Maybe()
				store.EXPECT().SaveCommitVerification(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
			}

			writeHandler := NewWriteCommitCCVNodeDataHandler(store, agg, lggr, sig, time.Millisecond)
			batchHandler := NewBatchWriteCommitVerifierNodeResultHandler(writeHandler, tc.maxBatchSize)

			requests := make([]*committeepb.WriteCommitteeVerifierNodeResultRequest, tc.numRequests)
			for i := range requests {
				requests[i] = makeValidProtoRequest()
			}

			ctx := auth.ToContext(context.Background(), auth.CreateCallerIdentity(testCallerID, false))
			resp, err := batchHandler.Handle(ctx, &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
				Requests: requests,
			})

			if tc.expectCode == codes.OK {
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.Len(t, resp.Responses, tc.numRequests)
			} else {
				require.Error(t, err)
				require.Equal(t, tc.expectCode, status.Code(err))
				require.Contains(t, err.Error(), tc.expectErrorMsg)
				require.Nil(t, resp)
			}
		})
	}
}

func TestBatchWriteCommitCCVNodeDataHandler_MixedSuccessAndInvalidArgument(t *testing.T) {
	t.Parallel()

	const testCallerID = "test-caller"

	lggr := logger.TestSugared(t)
	store := mocks.NewMockCommitVerificationStore(t)
	agg := mocks.NewMockAggregationTriggerer(t)

	signer := &model.SignerIdentifier{
		Identifier: []byte{0xAA},
	}
	sig := mocks.NewMockSignatureValidator(t)
	sig.EXPECT().ValidateSignature(mock.Anything, mock.Anything).Return(&model.SignatureValidationResult{
		Signer: signer,
	}, nil)
	sig.EXPECT().DeriveAggregationKey(mock.Anything, mock.Anything).Return("messageId", nil)

	agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything, testCallerID, time.Millisecond).Return(nil).Maybe()

	store.EXPECT().SaveCommitVerification(mock.Anything, mock.Anything, mock.Anything).Return(nil)

	writeHandler := NewWriteCommitCCVNodeDataHandler(store, agg, lggr, sig, time.Millisecond)
	batchHandler := NewBatchWriteCommitVerifierNodeResultHandler(writeHandler, 10)

	validReq := makeValidProtoRequest()
	invalidReq := makeValidProtoRequest()
	invalidReq.CommitteeVerifierNodeResult = nil

	ctx := auth.ToContext(context.Background(), auth.CreateCallerIdentity(testCallerID, false))
	resp, err := batchHandler.Handle(ctx, &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
		Requests: []*committeepb.WriteCommitteeVerifierNodeResultRequest{validReq, invalidReq},
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Responses, 2)
	require.Len(t, resp.Errors, 2)

	require.Equal(t, committeepb.WriteStatus_SUCCESS, resp.Responses[0].Status)
	require.NotNil(t, resp.Errors[0])
	require.Equal(t, int32(codes.OK), resp.Errors[0].Code)

	require.Equal(t, committeepb.WriteStatus_FAILED, resp.Responses[1].Status)
	require.NotNil(t, resp.Errors[1])
	require.Equal(t, int32(codes.InvalidArgument), resp.Errors[1].Code)
}
