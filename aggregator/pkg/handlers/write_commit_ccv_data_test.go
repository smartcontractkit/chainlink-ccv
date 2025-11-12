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

	"github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func makeValidProtoRequest(idempotencyKey string) *pb.WriteCommitCCVNodeDataRequest {
	msg, _ := protocol.NewMessage(1, 2, 1, nil, nil, 0, 500_000, nil, nil, []byte{}, []byte{}, nil)
	id, _ := msg.MessageID()
	pbMsg := model.MapProtocolMessageToProtoMessage(msg)
	return &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: &pb.MessageWithCCVNodeData{
			MessageId: id[:],
			CcvData:   []byte("x"),
			Timestamp: time.Now().UnixMilli(),
			Message:   pbMsg,
		},
		IdempotencyKey: idempotencyKey,
	}
}

func TestWriteCommitCCVNodeDataHandler_Handle_Table(t *testing.T) {
	t.Parallel()

	validUUID := "550e8400-e29b-41d4-a716-446655440000"

	signer1 := &model.IdentifierSigner{
		ParticipantID: "p1",
		Address:       []byte{0xAA},
		CommitteeID:   model.DefaultCommitteeID,
	}
	signer2 := &model.IdentifierSigner{
		ParticipantID: "p2",
		Address:       []byte{0xBB},
		CommitteeID:   model.DefaultCommitteeID,
	}

	type testCase struct {
		name              string
		req               *pb.WriteCommitCCVNodeDataRequest
		signers           []*model.IdentifierSigner
		sigErr            error
		saveErr           error
		aggErr            error
		expectGRPCCode    codes.Code
		expectStatus      pb.WriteStatus
		expectStoreCalls  int
		expectAggCalls    int
		expectCommitteeID model.CommitteeID
	}

	tests := []testCase{
		{
			name:              "success_single_signer_returns_success",
			req:               makeValidProtoRequest(validUUID),
			signers:           []*model.IdentifierSigner{signer1},
			expectGRPCCode:    codes.OK,
			expectStatus:      pb.WriteStatus_SUCCESS,
			expectStoreCalls:  1,
			expectAggCalls:    1,
			expectCommitteeID: model.DefaultCommitteeID,
		},
		{
			name:              "success_multiple_signers_stores_all_and_triggers_once",
			req:               makeValidProtoRequest(validUUID),
			signers:           []*model.IdentifierSigner{signer1, signer2},
			expectGRPCCode:    codes.OK,
			expectStatus:      pb.WriteStatus_SUCCESS,
			expectStoreCalls:  2,
			expectAggCalls:    1,
			expectCommitteeID: model.DefaultCommitteeID,
		},
		{
			name: "validation_enabled_missing_payload_invalid_argument",
			req: &pb.WriteCommitCCVNodeDataRequest{
				CcvNodeData:    nil, // triggers validation error
				IdempotencyKey: validUUID,
			},
			// Signature validation is never called
			expectGRPCCode:   codes.InvalidArgument,
			expectStatus:     pb.WriteStatus_FAILED,
			expectStoreCalls: 0,
			expectAggCalls:   0,
		},
		{
			name:             "invalid_idempotency_key_returns_invalid_argument",
			req:              makeValidProtoRequest("not-a-uuid"),
			signers:          []*model.IdentifierSigner{signer1},
			expectGRPCCode:   codes.InvalidArgument,
			expectStatus:     pb.WriteStatus_FAILED,
			expectStoreCalls: 0,
			expectAggCalls:   0,
		},
		{
			name:             "signature_validator_error_returns_internal",
			req:              makeValidProtoRequest(validUUID),
			signers:          nil,
			sigErr:           errors.New("sig-fail"),
			expectGRPCCode:   codes.Internal,
			expectStatus:     pb.WriteStatus_FAILED,
			expectStoreCalls: 0,
			expectAggCalls:   0,
		},
		{
			name:             "storage_error_returns_internal_and_no_aggregation",
			req:              makeValidProtoRequest(validUUID),
			signers:          []*model.IdentifierSigner{signer1},
			saveErr:          errors.New("db-down"),
			expectGRPCCode:   codes.Internal,
			expectStatus:     pb.WriteStatus_FAILED,
			expectStoreCalls: 1,
			expectAggCalls:   0,
		},
		{
			name:              "aggregation_channel_full_returns_resource_exhausted",
			req:               makeValidProtoRequest(validUUID),
			signers:           []*model.IdentifierSigner{signer1},
			aggErr:            common.ErrAggregationChannelFull,
			expectGRPCCode:    codes.ResourceExhausted,
			expectStatus:      pb.WriteStatus_FAILED,
			expectStoreCalls:  1,
			expectAggCalls:    1,
			expectCommitteeID: model.DefaultCommitteeID,
		},
		{
			name:              "aggregation_other_error_returns_internal",
			req:               makeValidProtoRequest(validUUID),
			signers:           []*model.IdentifierSigner{signer1},
			aggErr:            errors.New("agg-fail"),
			expectGRPCCode:    codes.Internal,
			expectStatus:      pb.WriteStatus_FAILED,
			expectStoreCalls:  1,
			expectAggCalls:    1,
			expectCommitteeID: model.DefaultCommitteeID,
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
				sig.EXPECT().ValidateSignature(mock.Anything, mock.Anything).Return(tc.signers, nil, nil).Maybe()
			}

			// Save expectations with counter
			savedCount := 0
			if tc.expectStoreCalls > 0 {
				store.EXPECT().SaveCommitVerification(mock.Anything, mock.MatchedBy(func(r *model.CommitVerificationRecord) bool {
					savedCount++
					if len(tc.signers) > 0 {
						require.Equal(t, tc.signers[0].CommitteeID, r.CommitteeID)
					}
					require.NotZero(t, r.IdempotencyKey)
					return true
				}), mock.Anything).Return(tc.saveErr).Times(tc.expectStoreCalls)
			} else {
				store.EXPECT().SaveCommitVerification(mock.Anything, mock.Anything, mock.Anything).Maybe()
			}

			// Aggregator expectations and capture
			aggCalled := 0
			var lastMsgID model.MessageID
			var lastCommittee model.CommitteeID
			var lastAggregation model.AggregationKey
			if tc.expectAggCalls > 0 {
				agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything, mock.Anything).Run(func(m model.MessageID, a model.AggregationKey, c model.CommitteeID) {
					aggCalled++
					lastMsgID = m
					lastCommittee = c
					lastAggregation = a
				}).Return(tc.aggErr).Times(tc.expectAggCalls)
			} else {
				agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything, mock.Anything).Maybe()
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
				require.Equal(t, tc.expectCommitteeID, lastCommittee)
				require.Len(t, lastMsgID, 32)
				require.NotEmpty(t, lastAggregation)
			}
		})
	}
}
