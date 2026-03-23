package middlewares

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
)

// grpcMethodKey is an unexported context key for storing the gRPC method name.
type grpcMethodKey struct{}

// GRPCStatsHandler is a gRPC server-side stats.Handler that records payload sizes and error counts.
// It uses wire-level sizes from InPayload/OutPayload so it captures the actual bytes on the wire,
// including transport encoding overhead. End events capture gRPC status codes (including
// transport-level errors such as ResourceExhausted from max-message-size enforcement, which
// happen before any unary interceptor runs).
type GRPCStatsHandler struct {
	m common.AggregatorMetricLabeler
}

// NewGRPCStatsHandler creates a new server-side gRPC stats handler.
func NewGRPCStatsHandler(m common.AggregatorMetricLabeler) *GRPCStatsHandler {
	return &GRPCStatsHandler{m: m}
}

func (h *GRPCStatsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return context.WithValue(ctx, grpcMethodKey{}, info.FullMethodName)
}

func (h *GRPCStatsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {
	method, ok := ctx.Value(grpcMethodKey{}).(string)
	if !ok {
		method = ""
	}

	switch st := s.(type) {
	case *stats.InPayload:
		h.m.RecordGRPCPayloadSize(ctx, method, "recv", st.WireLength)
	case *stats.OutPayload:
		h.m.RecordGRPCPayloadSize(ctx, method, "send", st.WireLength)
	case *stats.End:
		if st.Error != nil {
			code := status.Code(st.Error)
			if code != codes.OK {
				h.m.IncrementGRPCErrors(ctx, code.String(), method)
			}
		}
	}
}

func (h *GRPCStatsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (h *GRPCStatsHandler) HandleConn(_ context.Context, _ stats.ConnStats) {}
