package heartbeatclient

import (
	"context"
)

// NoopHeartbeatClient is a no-op implementation of HeartbeatSender.
type NoopHeartbeatClient struct{}

// NewNoopHeartbeatClient creates a new no-op heartbeat client.
func NewNoopHeartbeatClient() *NoopHeartbeatClient {
	return &NoopHeartbeatClient{}
}

// SendHeartbeat is a no-op implementation that returns a dummy response.
func (n *NoopHeartbeatClient) SendHeartbeat(ctx context.Context, blockHeightsByChain map[uint64]uint64) (HeartbeatResponse, error) {
	return HeartbeatResponse{
		AggregatorID:    "noop",
		Timestamp:       0,
		ChainBenchmarks: make(map[uint64]ChainBenchmark),
	}, nil
}

// Close is a no-op implementation.
func (n *NoopHeartbeatClient) Close() error {
	return nil
}

var _ HeartbeatSender = (*NoopHeartbeatClient)(nil)
