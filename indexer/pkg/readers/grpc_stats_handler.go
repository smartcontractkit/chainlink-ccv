package readers

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
)

// grpcMethodKey is an unexported context key for storing the gRPC method name.
type grpcMethodKey struct{}

// grpcClientStatsHandler is a gRPC client-side stats.Handler that records payload sizes and error counts.
// It uses wire-level sizes from OutPayload/InPayload so it captures the actual bytes on the wire.
// End events capture gRPC status codes including transport-level errors such as ResourceExhausted
// when an aggregator response exceeds the client's configured MaxRecvMsgSize.
type grpcClientStatsHandler struct {
	m common.IndexerMetricLabeler
}

func newGRPCClientStatsHandler(m common.IndexerMetricLabeler) *grpcClientStatsHandler {
	return &grpcClientStatsHandler{m: m}
}

func (h *grpcClientStatsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return context.WithValue(ctx, grpcMethodKey{}, info.FullMethodName)
}

func (h *grpcClientStatsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {
	method, ok := ctx.Value(grpcMethodKey{}).(string)
	if !ok {
		method = ""
	}

	switch st := s.(type) {
	case *stats.OutPayload:
		h.m.RecordGRPCPayloadSize(ctx, method, "send", st.WireLength)
	case *stats.InPayload:
		h.m.RecordGRPCPayloadSize(ctx, method, "recv", st.WireLength)
	case *stats.End:
		if st.Error != nil {
			code := status.Code(st.Error)
			if code != codes.OK {
				h.m.IncrementGRPCErrors(ctx, code.String(), method)
			}
		}
	}
}

func (h *grpcClientStatsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (h *grpcClientStatsHandler) HandleConn(_ context.Context, _ stats.ConnStats) {}

// grpcClientDialOptions returns the gRPC dial options for monitoring payload sizes and error counts.
func grpcClientDialOptions(m common.IndexerMetricLabeler) []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithStatsHandler(newGRPCClientStatsHandler(m)),
	}
}
