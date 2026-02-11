package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

func makeValidProtoRequest() *committeepb.WriteCommitteeVerifierNodeResultRequest {
	msg := makeTestMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.SequenceNumber(1), []byte{})
	pbMsg, err := ccvcommon.MapProtocolMessageToProtoMessage(msg)
	if err != nil {
		panic(err)
	}

	executorAddr := makeTestExecutorAddress()
	ccvAddresses := [][]byte{make([]byte, 20)}
	hash, err := protocol.ComputeCCVAndExecutorHash(
		[]protocol.UnknownAddress{ccvAddresses[0]},
		executorAddr,
	)
	if err != nil {
		panic(err)
	}
	pbMsg.CcvAndExecutorHash = hash[:]

	return &committeepb.WriteCommitteeVerifierNodeResultRequest{
		CommitteeVerifierNodeResult: &committeepb.CommitteeVerifierNodeResult{
			Signature:       []byte("signature_bytes"),
			CcvVersion:      []byte{0x1, 0x2, 0x3, 0x4},
			Message:         pbMsg,
			CcvAddresses:    ccvAddresses,
			ExecutorAddress: executorAddr,
		},
	}
}

func TestWriteCommitCCVNodeDataHandler_Handle_Table(t *testing.T) {
	t.Parallel()

	const testCallerID = "test-caller"
	const testChannelKey model.ChannelKey = "test-caller"

	signer1 := &model.SignerIdentifier{
		Identifier: []byte{0xAA},
	}

	type testCase struct {
		name                 string
		req                  *committeepb.WriteCommitteeVerifierNodeResultRequest
		signer               *model.SignerIdentifier
		sigErr               error
		rateLimitErr         error
		rateLimitInternalErr error
		saveErr              error
		aggErr               error
		expectGRPCCode       codes.Code
		expectStatus         committeepb.WriteStatus
		expectStoreCalls     int
		expectAggCalls       int
	}

	tests := []testCase{
		{
			name:             "success_single_signer_returns_success",
			req:              makeValidProtoRequest(),
			signer:           signer1,
			expectGRPCCode:   codes.OK,
			expectStatus:     committeepb.WriteStatus_SUCCESS,
			expectStoreCalls: 1,
			expectAggCalls:   1,
		},
		{
			name: "validation_enabled_missing_payload_invalid_argument",
			req: &committeepb.WriteCommitteeVerifierNodeResultRequest{
				CommitteeVerifierNodeResult: nil,
			},
			// Signature validation is never called
			expectGRPCCode:   codes.InvalidArgument,
			expectStatus:     committeepb.WriteStatus_FAILED,
			expectStoreCalls: 0,
			expectAggCalls:   0,
		},
		{
			name:             "signature_validator_error_returns_invalid_argument",
			req:              makeValidProtoRequest(),
			signer:           nil,
			sigErr:           errors.New("sig-fail"),
			expectGRPCCode:   codes.InvalidArgument,
			expectStatus:     committeepb.WriteStatus_FAILED,
			expectStoreCalls: 0,
			expectAggCalls:   0,
		},
		{
			name:             "storage_error_returns_internal_and_no_aggregation",
			req:              makeValidProtoRequest(),
			signer:           signer1,
			saveErr:          errors.New("db-down"),
			expectGRPCCode:   codes.Internal,
			expectStatus:     committeepb.WriteStatus_FAILED,
			expectStoreCalls: 1,
			expectAggCalls:   0,
		},
		{
			name:             "aggregation_channel_full_returns_resource_exhausted",
			req:              makeValidProtoRequest(),
			signer:           signer1,
			aggErr:           common.ErrAggregationChannelFull,
			expectGRPCCode:   codes.ResourceExhausted,
			expectStatus:     committeepb.WriteStatus_FAILED,
			expectStoreCalls: 1,
			expectAggCalls:   1,
		},
		{
			name:             "aggregation_other_error_returns_internal",
			req:              makeValidProtoRequest(),
			signer:           signer1,
			aggErr:           errors.New("agg-fail"),
			expectGRPCCode:   codes.Internal,
			expectStatus:     committeepb.WriteStatus_FAILED,
			expectStoreCalls: 1,
			expectAggCalls:   1,
		},
		{
			name:             "verification_rate_limit_exceeded_returns_resource_exhausted",
			req:              makeValidProtoRequest(),
			signer:           signer1,
			rateLimitErr:     errors.New("rate limit exceeded"),
			expectGRPCCode:   codes.ResourceExhausted,
			expectStatus:     committeepb.WriteStatus_FAILED,
			expectStoreCalls: 0,
			expectAggCalls:   0,
		},
		{
			name:                 "verification_rate_limiter_internal_error_fails_open",
			req:                  makeValidProtoRequest(),
			signer:               signer1,
			rateLimitInternalErr: errors.New("redis unavailable"),
			expectGRPCCode:       codes.OK,
			expectStatus:         committeepb.WriteStatus_SUCCESS,
			expectStoreCalls:     1,
			expectAggCalls:       1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lggr := logger.TestSugared(t)

			// Mocks
			store := mocks.NewMockCommitVerificationStore(t)
			agg := mocks.NewMockAggregationTriggerer(t)
			sig := mocks.NewMockSignatureValidator(t)
			rateLimiter := mocks.NewMockVerificationRateLimiter(t)

			sig.EXPECT().DeriveAggregationKey(mock.Anything, mock.Anything).Return("messageId", nil).Maybe()

			if tc.rateLimitErr != nil {
				rateLimiter.EXPECT().TryAcquire(mock.Anything, mock.Anything, mock.Anything).Return(model.TryAcquireResult{IsReached: true}, nil).Once()
			} else if tc.rateLimitInternalErr != nil {
				rateLimiter.EXPECT().TryAcquire(mock.Anything, mock.Anything, mock.Anything).Return(model.TryAcquireResult{}, tc.rateLimitInternalErr).Once()
			} else if tc.signer != nil {
				rateLimiter.EXPECT().TryAcquire(mock.Anything, mock.Anything, mock.Anything).Return(model.TryAcquireResult{}, nil).Maybe()
			}

			// Signature validator expectation
			if tc.sigErr != nil {
				sig.EXPECT().ValidateSignature(mock.Anything, mock.Anything).Return(nil, tc.sigErr)
			} else {
				sig.EXPECT().ValidateSignature(mock.Anything, mock.Anything).Return(&model.SignatureValidationResult{
					Signer: tc.signer,
				}, nil).Maybe()
			}

			// Save expectations with counter
			savedCount := 0
			if tc.expectStoreCalls > 0 {
				store.EXPECT().SaveCommitVerification(mock.Anything, mock.Anything, mock.Anything).Run(func(ctx context.Context, r *model.CommitVerificationRecord, key model.AggregationKey) {
					savedCount++
				}).Return(tc.saveErr).Times(tc.expectStoreCalls)
			} else {
				store.EXPECT().SaveCommitVerification(mock.Anything, mock.Anything, mock.Anything).Maybe()
			}

			// Aggregator expectations and capture
			aggCalled := 0
			var lastMsgID model.MessageID
			var lastAggregation model.AggregationKey
			if tc.expectAggCalls > 0 {
				agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything, testChannelKey, time.Millisecond).Run(func(m model.MessageID, a model.AggregationKey, c model.ChannelKey, d time.Duration) {
					aggCalled++
					lastMsgID = m
					lastAggregation = a
				}).Return(tc.aggErr).Times(tc.expectAggCalls)
			} else {
				agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe()
			}

			mon := mocks.NewMockAggregatorMonitoring(t)
			labeler := mocks.NewMockAggregatorMetricLabeler(t)
			mon.EXPECT().Metrics().Return(labeler).Maybe()
			labeler.EXPECT().With(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(labeler).Maybe()
			labeler.EXPECT().IncrementVerificationsTotal(mock.Anything).Maybe()

			handler := NewWriteCommitCCVNodeDataHandler(store, agg, mon, lggr, sig, rateLimiter, time.Millisecond)

			ctx := auth.ToContext(context.Background(), auth.CreateCallerIdentity(testCallerID, false))
			resp, err := handler.Handle(ctx, tc.req)

			// gRPC status code assertions
			if tc.expectGRPCCode == codes.OK {
				require.NoError(t, err, "expected no error")
			} else {
				require.Error(t, err, "expected error")
				require.Equal(t, tc.expectGRPCCode, status.Code(err), "unexpected grpc code")
			}

			require.NotNil(t, resp)
			require.Equal(t, tc.expectStatus, resp.Status)

			require.Equal(t, tc.expectStoreCalls, savedCount, "unexpected SaveCommitVerification call count")
			require.Equal(t, tc.expectAggCalls, aggCalled, "unexpected CheckAggregation call count")
			if tc.expectAggCalls > 0 {
				require.Len(t, lastMsgID, 32)
				require.NotEmpty(t, lastAggregation)
			}
		})
	}
}
