package heartbeatclient

import (
	"context"
	"time"

	"google.golang.org/grpc"

	heartbeatpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/heartbeat/v1"
)

// NoopHeartbeatClient is a no-op implementation of HeartbeatServiceClient.
type NoopHeartbeatClient struct{}

// NewNoopHeartbeatClient creates a new no-op heartbeat client.
func NewNoopHeartbeatClient() *NoopHeartbeatClient {
	return &NoopHeartbeatClient{}
}

// SendHeartbeat is a no-op implementation that returns a dummy response.
func (n *NoopHeartbeatClient) SendHeartbeat(ctx context.Context, in *heartbeatpb.HeartbeatRequest, opts ...grpc.CallOption) (*heartbeatpb.HeartbeatResponse, error) {
	return &heartbeatpb.HeartbeatResponse{
		Timestamp:       time.Now().Unix(),
		AggregatorId:    "noop",
		ChainBenchmarks: make(map[uint64]*heartbeatpb.ChainBenchmark),
	}, nil
}

var _ heartbeatpb.HeartbeatServiceClient = (*NoopHeartbeatClient)(nil)
