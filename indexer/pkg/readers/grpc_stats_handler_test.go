package readers

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
	h := newGRPCClientStatsHandler(mocks.NewMockIndexerMetricLabeler(t))
	return h.TagRPC(context.Background(), &stats.RPCTagInfo{FullMethodName: testMethod})
}

func TestGRPCClientStatsHandler_TagRPC(t *testing.T) {
	h := newGRPCClientStatsHandler(mocks.NewMockIndexerMetricLabeler(t))
	ctx := h.TagRPC(context.Background(), &stats.RPCTagInfo{FullMethodName: testMethod})
	assert.Equal(t, testMethod, ctx.Value(grpcMethodKey{}))
}

func TestGRPCClientStatsHandler_HandleRPC_OutPayload(t *testing.T) {
	m := mocks.NewMockIndexerMetricLabeler(t)
	m.EXPECT().RecordGRPCPayloadSize(mock.Anything, testMethod, "send", 1024).Once()

	h := newGRPCClientStatsHandler(m)
	h.HandleRPC(taggedCtx(t), &stats.OutPayload{WireLength: 1024})
}

func TestGRPCClientStatsHandler_HandleRPC_InPayload(t *testing.T) {
	m := mocks.NewMockIndexerMetricLabeler(t)
	m.EXPECT().RecordGRPCPayloadSize(mock.Anything, testMethod, "recv", 2048).Once()

	h := newGRPCClientStatsHandler(m)
	h.HandleRPC(taggedCtx(t), &stats.InPayload{WireLength: 2048})
}

func TestGRPCClientStatsHandler_HandleRPC_End_NonOKError(t *testing.T) {
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
			m := mocks.NewMockIndexerMetricLabeler(t)
			m.EXPECT().IncrementGRPCErrors(mock.Anything, tc.code.String(), testMethod).Once()

			h := newGRPCClientStatsHandler(m)
			h.HandleRPC(taggedCtx(t), &stats.End{Error: status.Error(tc.code, "error")})
		})
	}
}

func TestGRPCClientStatsHandler_HandleRPC_End_NoError(t *testing.T) {
	m := mocks.NewMockIndexerMetricLabeler(t)
	// No metric calls expected on success.

	h := newGRPCClientStatsHandler(m)
	h.HandleRPC(taggedCtx(t), &stats.End{Error: nil})
}

func TestGRPCClientStatsHandler_HandleRPC_End_OKError(t *testing.T) {
	m := mocks.NewMockIndexerMetricLabeler(t)
	// codes.OK wrapped as an error should not increment the error counter.

	h := newGRPCClientStatsHandler(m)
	h.HandleRPC(taggedCtx(t), &stats.End{Error: status.Error(codes.OK, "ok")})
}

func TestGRPCClientStatsHandler_HandleRPC_UnknownMethod(t *testing.T) {
	m := mocks.NewMockIndexerMetricLabeler(t)
	// Context without a tagged method — method falls back to empty string.
	m.EXPECT().RecordGRPCPayloadSize(mock.Anything, "", "send", 512).Once()

	h := newGRPCClientStatsHandler(m)
	h.HandleRPC(context.Background(), &stats.OutPayload{WireLength: 512})
}

func TestGRPCClientStatsHandler_HandleRPC_IgnoredEvents(t *testing.T) {
	m := mocks.NewMockIndexerMetricLabeler(t)
	// Begin, InHeader, OutHeader — no metric calls expected.

	h := newGRPCClientStatsHandler(m)
	h.HandleRPC(taggedCtx(t), &stats.Begin{})
	h.HandleRPC(taggedCtx(t), &stats.InHeader{})
	h.HandleRPC(taggedCtx(t), &stats.OutHeader{})
}

func TestGRPCClientStatsHandler_TagConn(t *testing.T) {
	h := newGRPCClientStatsHandler(mocks.NewMockIndexerMetricLabeler(t))
	ctx := h.TagConn(context.Background(), &stats.ConnTagInfo{})
	assert.Equal(t, context.Background(), ctx)
}

func TestGRPCClientStatsHandler_HandleConn(t *testing.T) {
	h := newGRPCClientStatsHandler(mocks.NewMockIndexerMetricLabeler(t))
	// Must not panic.
	h.HandleConn(context.Background(), &stats.ConnBegin{})
}

func TestGRPCClientDialOptions(t *testing.T) {
	m := mocks.NewMockIndexerMetricLabeler(t)
	opts := grpcClientDialOptions(m)
	assert.Len(t, opts, 1)
}
