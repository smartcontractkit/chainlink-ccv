package handlers

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/testutil"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	messagerules "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
	commontracing "github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

func TestBatchWriteCommitCCVNodeDataHandler_BatchSizeValidation(t *testing.T) {
	t.Parallel()

	const testCallerID = "test-caller"
	const testChannelKey model.ChannelKey = "test-caller"

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

			lggr := logger.Sugared(logger.Nop())
			store := mocks.NewMockCommitVerificationStore(t)
			agg := mocks.NewMockAggregationTriggerer(t)
			sig := mocks.NewMockSignatureValidator(t)

			signer := &model.SignerIdentifier{Identifier: []byte{0xAA}}

			if tc.expectCode == codes.OK {
				sig.EXPECT().ValidateSignature(mock.Anything, mock.Anything).Return(&model.SignatureValidationResult{
					Signer: signer,
				}, nil).Maybe()
				sig.EXPECT().DeriveAggregationKey(mock.Anything, mock.Anything).Return("messageId", nil).Maybe()
				agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything, mock.Anything, testChannelKey).Return(nil).Maybe()
				store.EXPECT().SaveCommitVerification(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
			}

			mon := mocks.NewMockAggregatorMonitoring(t)
			testutil.StubTracing(mon)
			labeler := mocks.NewMockAggregatorMetricLabeler(t)
			mon.EXPECT().Metrics().Return(labeler).Maybe()
			labeler.EXPECT().With(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(labeler).Maybe()
			labeler.EXPECT().IncrementVerificationsTotal(mock.Anything).Maybe()

			writeHandler := NewWriteCommitCCVNodeDataHandler(store, agg, mon, lggr, sig, messagerules.NoopChecker{})
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
	const testChannelKey model.ChannelKey = "test-caller"

	lggr := logger.Sugared(logger.Nop())
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

	agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything, mock.Anything, testChannelKey).Return(nil).Maybe()

	store.EXPECT().SaveCommitVerification(mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mon := mocks.NewMockAggregatorMonitoring(t)
	testutil.StubTracing(mon)
	labeler := mocks.NewMockAggregatorMetricLabeler(t)
	mon.EXPECT().Metrics().Return(labeler).Maybe()
	labeler.EXPECT().With(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(labeler).Maybe()
	labeler.EXPECT().IncrementVerificationsTotal(mock.Anything).Maybe()

	writeHandler := NewWriteCommitCCVNodeDataHandler(store, agg, mon, lggr, sig, messagerules.NoopChecker{})
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

func TestBatchWriteCommitCCVNodeDataHandler_NilRequestAtIndexReturnsInvalidArgument(t *testing.T) {
	t.Parallel()

	const testCallerID = "test-caller"
	const testChannelKey model.ChannelKey = "test-caller"

	lggr := logger.Sugared(logger.Nop())
	store := mocks.NewMockCommitVerificationStore(t)
	agg := mocks.NewMockAggregationTriggerer(t)
	sig := mocks.NewMockSignatureValidator(t)

	signer := &model.SignerIdentifier{Identifier: []byte{0xAA}}
	sig.EXPECT().ValidateSignature(mock.Anything, mock.Anything).Return(&model.SignatureValidationResult{
		Signer: signer,
	}, nil)
	sig.EXPECT().DeriveAggregationKey(mock.Anything, mock.Anything).Return("messageId", nil)
	agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything, mock.Anything, testChannelKey).Return(nil)
	store.EXPECT().SaveCommitVerification(mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mon := mocks.NewMockAggregatorMonitoring(t)
	testutil.StubTracing(mon)
	labeler := mocks.NewMockAggregatorMetricLabeler(t)
	mon.EXPECT().Metrics().Return(labeler).Maybe()
	labeler.EXPECT().With(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(labeler).Maybe()
	labeler.EXPECT().IncrementVerificationsTotal(mock.Anything).Maybe()

	writeHandler := NewWriteCommitCCVNodeDataHandler(store, agg, mon, lggr, sig, messagerules.NoopChecker{})
	batchHandler := NewBatchWriteCommitVerifierNodeResultHandler(writeHandler, 10)

	validReq := makeValidProtoRequest()

	ctx := auth.ToContext(context.Background(), auth.CreateCallerIdentity(testCallerID, false))
	resp, err := batchHandler.Handle(ctx, &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
		Requests: []*committeepb.WriteCommitteeVerifierNodeResultRequest{validReq, nil},
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
	require.Contains(t, resp.Errors[1].Message, "nil request at index 1")
}

func TestBatchWriteCommitCCVNodeDataHandler_CancelledContextReturnsImmediately(t *testing.T) {
	t.Parallel()

	const testCallerID = "test-caller"
	const testChannelKey model.ChannelKey = "test-caller"
	blockDuration := 5 * time.Second

	// Use a nop logger: worker goroutines that are still running when the context
	// is canceled may log after this test's *testing.T is torn down, which
	// panics in Go. A nop logger avoids that without changing the handler.
	lggr := logger.Sugared(logger.Nop())
	store := mocks.NewMockCommitVerificationStore(t)
	agg := mocks.NewMockAggregationTriggerer(t)
	sig := mocks.NewMockSignatureValidator(t)

	signer := &model.SignerIdentifier{Identifier: []byte{0xAA}}
	sig.EXPECT().ValidateSignature(mock.Anything, mock.Anything).Return(&model.SignatureValidationResult{
		Signer: signer,
	}, nil).Maybe()
	sig.EXPECT().DeriveAggregationKey(mock.Anything, mock.Anything).Return("messageId", nil).Maybe()
	store.EXPECT().SaveCommitVerification(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything, mock.Anything, testChannelKey).
		RunAndReturn(func(ctx context.Context, _ model.MessageID, _ model.AggregationKey, _ model.ChannelKey) error {
			<-ctx.Done()
			return ctx.Err()
		}).Maybe()

	mon := mocks.NewMockAggregatorMonitoring(t)
	testutil.StubTracing(mon)
	labeler := mocks.NewMockAggregatorMetricLabeler(t)
	mon.EXPECT().Metrics().Return(labeler).Maybe()
	labeler.EXPECT().With(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(labeler).Maybe()
	labeler.EXPECT().IncrementVerificationsTotal(mock.Anything).Maybe()

	writeHandler := NewWriteCommitCCVNodeDataHandler(store, agg, mon, lggr, sig, messagerules.NoopChecker{})
	batchHandler := NewBatchWriteCommitVerifierNodeResultHandler(writeHandler, 10)

	ctx, cancel := context.WithCancel(auth.ToContext(context.Background(), auth.CreateCallerIdentity(testCallerID, false)))
	defer cancel()

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	resp, err := batchHandler.Handle(ctx, &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
		Requests: []*committeepb.WriteCommitteeVerifierNodeResultRequest{makeValidProtoRequest()},
	})
	elapsed := time.Since(start)

	require.Error(t, err)
	require.Equal(t, codes.Canceled, status.Code(err))
	require.Nil(t, resp)
	require.Less(t, elapsed, blockDuration, "handler should return promptly on context cancellation, not block for maxBlockTime")
}

// capturingTracing is a commontracing.Tracing that records, per messageID, the parent
// SpanContext observed in ctx when StartMessageSpan is called - used to verify each batch
// item's traceparent metadata reaches its own child write, not a different item's.
type capturingTracing struct {
	mu      sync.Mutex
	parents map[protocol.Bytes32]oteltrace.SpanContext
}

func newCapturingTracing() *capturingTracing {
	return &capturingTracing{parents: make(map[protocol.Bytes32]oteltrace.SpanContext)}
}

func (c *capturingTracing) StartMessageSpan(ctx context.Context, _ string, messageID protocol.Bytes32, _ ...commontracing.SpanOption) (context.Context, oteltrace.Span) {
	c.mu.Lock()
	c.parents[messageID] = oteltrace.SpanContextFromContext(ctx)
	c.mu.Unlock()
	return ctx, oteltrace.SpanFromContext(ctx)
}

func (c *capturingTracing) parentFor(t *testing.T, messageID protocol.Bytes32) oteltrace.SpanContext {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	sc, ok := c.parents[messageID]
	require.True(t, ok, "no span was started for messageID %s", messageID)
	return sc
}

// makeValidProtoRequestWithSeq is makeValidProtoRequest with a distinct sequence number,
// so each call produces a distinct MessageID to key capturingTracing's parents by.
func makeValidProtoRequestWithSeq(t *testing.T, seqNum protocol.SequenceNumber) (*committeepb.WriteCommitteeVerifierNodeResultRequest, protocol.Bytes32) {
	t.Helper()
	msg := makeTestMessage(protocol.ChainSelector(1), protocol.ChainSelector(2), seqNum, []byte{})
	pbMsg, err := ccvcommon.MapProtocolMessageToProtoMessage(msg)
	require.NoError(t, err)

	executorAddr := makeTestExecutorAddress()
	ccvAddresses := [][]byte{make([]byte, 20)}
	hash, err := protocol.ComputeCCVAndExecutorHash([]protocol.UnknownAddress{ccvAddresses[0]}, executorAddr)
	require.NoError(t, err)
	pbMsg.CcvAndExecutorHash = hash[:]

	protoResult := &committeepb.CommitteeVerifierNodeResult{
		Signature:       []byte("signature_bytes"),
		CcvVersion:      []byte{0x1, 0x2, 0x3, 0x4},
		Message:         pbMsg,
		CcvAddresses:    ccvAddresses,
		ExecutorAddress: executorAddr,
	}

	// Compute messageID the same way the handler does (via the proto round-trip), rather
	// than from msg directly - proto mapping normalizes some fields (e.g. nil vs.
	// zero-length addresses), so the two can otherwise disagree on the resulting hash.
	record, err := model.CommitVerificationRecordFromProto(protoResult)
	require.NoError(t, err)
	var messageID protocol.Bytes32
	copy(messageID[:], record.MessageID)

	return &committeepb.WriteCommitteeVerifierNodeResultRequest{CommitteeVerifierNodeResult: protoResult}, messageID
}

// spanContextFromTraceParent extracts the SpanContext a traceparent header decodes to,
// via the same propagator production code uses, so expectations aren't hand-rolled.
func spanContextFromTraceParent(tp string) oteltrace.SpanContext {
	carrier := propagation.MapCarrier{"traceparent": tp}
	ctx := propagation.TraceContext{}.Extract(context.Background(), carrier)
	return oteltrace.SpanContextFromContext(ctx)
}

// TestBatchWriteCommitCCVNodeDataHandler_PerItemTraceParents asserts the per-item
// traceparent contract end to end through the batch handler: each item's metadata entry
// must parent its own child write, in request order - a regression here (e.g. losing the
// index, or reusing one shared ctx) would silently reconnect a batch item to the wrong
// trace while every other test in this file still passes.
func TestBatchWriteCommitCCVNodeDataHandler_PerItemTraceParents(t *testing.T) {
	// The production propagator is installed globally via beholder.SetGlobalOtelProviders;
	// pin it here so Inject/Extract behave deterministically regardless of test order.
	prevPropagator := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { otel.SetTextMapPropagator(prevPropagator) })

	const testCallerID = "test-caller"
	const testChannelKey model.ChannelKey = "test-caller"

	lggr := logger.Sugared(logger.Nop())
	store := mocks.NewMockCommitVerificationStore(t)
	agg := mocks.NewMockAggregationTriggerer(t)
	sig := mocks.NewMockSignatureValidator(t)

	signer := &model.SignerIdentifier{Identifier: []byte{0xAA}}
	sig.EXPECT().ValidateSignature(mock.Anything, mock.Anything).Return(&model.SignatureValidationResult{Signer: signer}, nil)
	sig.EXPECT().DeriveAggregationKey(mock.Anything, mock.Anything).Return("messageId", nil)
	agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything, mock.Anything, testChannelKey).Return(nil)
	store.EXPECT().SaveCommitVerification(mock.Anything, mock.Anything, mock.Anything).Return(nil)

	tracing := newCapturingTracing()
	mon := mocks.NewMockAggregatorMonitoring(t)
	mon.EXPECT().Tracing().Return(tracing)
	labeler := mocks.NewMockAggregatorMetricLabeler(t)
	mon.EXPECT().Metrics().Return(labeler).Maybe()
	labeler.EXPECT().With(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(labeler).Maybe()
	labeler.EXPECT().IncrementVerificationsTotal(mock.Anything).Maybe()

	writeHandler := NewWriteCommitCCVNodeDataHandler(store, agg, mon, lggr, sig, messagerules.NoopChecker{})
	batchHandler := NewBatchWriteCommitVerifierNodeResultHandler(writeHandler, 10)

	req0, msgID0 := makeValidProtoRequestWithSeq(t, 1)
	req1, msgID1 := makeValidProtoRequestWithSeq(t, 2)
	require.NotEqual(t, msgID0, msgID1)

	const tp0 = "00-11111111111111111111111111111111-1111111111111111-01"
	const tp1 = "00-22222222222222222222222222222222-2222222222222222-01"

	ctx := auth.ToContext(context.Background(), auth.CreateCallerIdentity(testCallerID, false))
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(
		commontracing.ItemTraceParentMetadataHeader, tp0,
		commontracing.ItemTraceParentMetadataHeader, tp1,
	))

	resp, err := batchHandler.Handle(ctx, &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
		Requests: []*committeepb.WriteCommitteeVerifierNodeResultRequest{req0, req1},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Responses, 2)

	gotSC0 := tracing.parentFor(t, msgID0)
	gotSC1 := tracing.parentFor(t, msgID1)
	wantSC0 := spanContextFromTraceParent(tp0)
	wantSC1 := spanContextFromTraceParent(tp1)

	require.Equal(t, wantSC0.TraceID(), gotSC0.TraceID(), "item 0 must parent off its own traceparent")
	require.Equal(t, wantSC0.SpanID(), gotSC0.SpanID(), "item 0 must parent off its own traceparent")
	require.Equal(t, wantSC1.TraceID(), gotSC1.TraceID(), "item 1 must parent off its own traceparent")
	require.Equal(t, wantSC1.SpanID(), gotSC1.SpanID(), "item 1 must parent off its own traceparent")
	require.NotEqual(t, gotSC0.TraceID(), gotSC1.TraceID(), "item 0 and item 1 must not share a parent")
}
