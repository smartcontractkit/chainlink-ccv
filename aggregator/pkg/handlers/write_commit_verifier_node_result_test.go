package handlers

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

func makeValidProtoRequest() *committeepb.WriteCommitteeVerifierNodeResultRequest {
	msg := makeTestMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), protocol.SequenceNumber(1), []byte{})
	pbMsg := ccvcommon.MapProtocolMessageToProtoMessage(msg)
	return &committeepb.WriteCommitteeVerifierNodeResultRequest{
		CommitteeVerifierNodeResult: &committeepb.CommitteeVerifierNodeResult{
			Signature:       []byte("signature_bytes"),
			CcvVersion:      []byte{0x1, 0x2, 0x3, 0x4},
			Message:         pbMsg,
			CcvAddresses:    [][]byte{},
			ExecutorAddress: makeTestExecutorAddress(),
		},
	}
}

func TestWriteCommitCCVNodeDataHandler_Handle_Table(t *testing.T) {
	t.Parallel()

	signer1 := &model.IdentifierSigner{
		Address: []byte{0xAA},
	}

	type testCase struct {
		name             string
		req              *committeepb.WriteCommitteeVerifierNodeResultRequest
		signer           *model.IdentifierSigner
		sigErr           error
		saveErr          error
		aggErr           error
		expectGRPCCode   codes.Code
		expectStatus     committeepb.WriteStatus
		expectStoreCalls int
		expectAggCalls   int
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
			name:             "signature_validator_error_returns_internal",
			req:              makeValidProtoRequest(),
			signer:           nil,
			sigErr:           errors.New("sig-fail"),
			expectGRPCCode:   codes.Internal,
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lggr := logger.TestSugared(t)

			// Mocks
			store := aggregation_mocks.NewMockCommitVerificationStore(t)
			agg := aggregation_mocks.NewMockAggregationTriggerer(t)
			sig := aggregation_mocks.NewMockSignatureValidator(t)

			sig.EXPECT().DeriveAggregationKey(mock.Anything, mock.Anything).Return("messageId", nil).Maybe()

			// Signature validator expectation
			if tc.sigErr != nil {
				sig.EXPECT().ValidateSignature(mock.Anything, mock.Anything).Return(nil, nil, tc.sigErr)
			} else {
				sig.EXPECT().ValidateSignature(mock.Anything, mock.Anything).Return(tc.signer, nil, nil).Maybe()
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
				agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything).Run(func(m model.MessageID, a model.AggregationKey) {
					aggCalled++
					lastMsgID = m
					lastAggregation = a
				}).Return(tc.aggErr).Times(tc.expectAggCalls)
			} else {
				agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything).Maybe()
			}

			handler := NewWriteCommitCCVNodeDataHandler(store, agg, lggr, sig)

			resp, err := handler.Handle(context.Background(), tc.req)

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
