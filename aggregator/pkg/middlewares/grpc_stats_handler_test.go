package middlewares

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
)

const testMethod = "/pkg.Service/Method"

func taggedCtx(t *testing.T) context.Context {
	t.Helper()
	h := NewGRPCStatsHandler(mocks.NewMockAggregatorMetricLabeler(t))
	return h.TagRPC(context.Background(), &stats.RPCTagInfo{FullMethodName: testMethod})
}

func TestGRPCStatsHandler_TagRPC(t *testing.T) {
	h := NewGRPCStatsHandler(mocks.NewMockAggregatorMetricLabeler(t))
	ctx := h.TagRPC(context.Background(), &stats.RPCTagInfo{FullMethodName: testMethod})
	assert.Equal(t, testMethod, ctx.Value(grpcMethodKey{}))
}

func TestGRPCStatsHandler_HandleRPC_InPayload(t *testing.T) {
	m := mocks.NewMockAggregatorMetricLabeler(t)
	m.EXPECT().RecordGRPCPayloadSize(mock.Anything, testMethod, "recv", 1024).Once()

	h := NewGRPCStatsHandler(m)
	h.HandleRPC(taggedCtx(t), &stats.InPayload{WireLength: 1024})
}

func TestGRPCStatsHandler_HandleRPC_OutPayload(t *testing.T) {
	m := mocks.NewMockAggregatorMetricLabeler(t)
	m.EXPECT().RecordGRPCPayloadSize(mock.Anything, testMethod, "send", 2048).Once()

	h := NewGRPCStatsHandler(m)
	h.HandleRPC(taggedCtx(t), &stats.OutPayload{WireLength: 2048})
}

func TestGRPCStatsHandler_HandleRPC_End_NonOKError(t *testing.T) {
	cases := []struct {
		name string
		code codes.Code
	}{
		{"ResourceExhausted", codes.ResourceExhausted},
		{"Internal", codes.Internal},
		{"Unavailable", codes.Unavailable},
		{"DeadlineExceeded", codes.DeadlineExceeded},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := mocks.NewMockAggregatorMetricLabeler(t)
			m.EXPECT().IncrementGRPCErrors(mock.Anything, tc.code.String(), testMethod).Once()

			h := NewGRPCStatsHandler(m)
			h.HandleRPC(taggedCtx(t), &stats.End{Error: status.Error(tc.code, "error")})
		})
	}
}

func TestGRPCStatsHandler_HandleRPC_End_NoError(t *testing.T) {
	m := mocks.NewMockAggregatorMetricLabeler(t)
	// No metric calls expected on success.

	h := NewGRPCStatsHandler(m)
	h.HandleRPC(taggedCtx(t), &stats.End{Error: nil})
}

func TestGRPCStatsHandler_HandleRPC_End_OKError(t *testing.T) {
	m := mocks.NewMockAggregatorMetricLabeler(t)
	// codes.OK wrapped as an error should not increment the error counter.

	h := NewGRPCStatsHandler(m)
	h.HandleRPC(taggedCtx(t), &stats.End{Error: status.Error(codes.OK, "ok")})
}

func TestGRPCStatsHandler_HandleRPC_UnknownMethod(t *testing.T) {
	m := mocks.NewMockAggregatorMetricLabeler(t)
	// Context without a tagged method — method falls back to empty string.
	m.EXPECT().RecordGRPCPayloadSize(mock.Anything, "", "recv", 512).Once()

	h := NewGRPCStatsHandler(m)
	h.HandleRPC(context.Background(), &stats.InPayload{WireLength: 512})
}

func TestGRPCStatsHandler_HandleRPC_IgnoredEvents(t *testing.T) {
	m := mocks.NewMockAggregatorMetricLabeler(t)
	// Begin, InHeader, OutHeader, InTrailer, OutTrailer — no metric calls expected.

	h := NewGRPCStatsHandler(m)
	h.HandleRPC(taggedCtx(t), &stats.Begin{})
	h.HandleRPC(taggedCtx(t), &stats.InHeader{})
	h.HandleRPC(taggedCtx(t), &stats.OutHeader{})
}

func TestGRPCStatsHandler_TagConn(t *testing.T) {
	h := NewGRPCStatsHandler(mocks.NewMockAggregatorMetricLabeler(t))
	ctx := h.TagConn(context.Background(), &stats.ConnTagInfo{})
	assert.Equal(t, context.Background(), ctx)
}

func TestGRPCStatsHandler_HandleConn(t *testing.T) {
	h := NewGRPCStatsHandler(mocks.NewMockAggregatorMetricLabeler(t))
	// Must not panic.
	h.HandleConn(context.Background(), &stats.ConnBegin{})
}
