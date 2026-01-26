package heartbeatclient

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	heartbeatpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/heartbeat/v1"
)

// Monitoring provides monitoring functionality for heartbeat clients.
// Services using the heartbeat client should provide an adapter implementing this interface.
type Monitoring interface {
	// Metrics returns the metrics labeler.
	Metrics() MetricLabeler
}

// MetricLabeler provides metric recording functionality for heartbeat operations.
type MetricLabeler interface {
	// With returns a new metrics labeler with the given key-value pairs.
	With(keyValues ...string) MetricLabeler

	// RecordHeartbeatDuration records the duration of a heartbeat operation.
	RecordHeartbeatDuration(ctx context.Context, duration time.Duration)

	// IncrementHeartbeatsSent increments the counter for successfully sent heartbeats.
	IncrementHeartbeatsSent(ctx context.Context)

	// IncrementHeartbeatsFailed increments the counter for failed heartbeat attempts.
	IncrementHeartbeatsFailed(ctx context.Context)

	// SetVerifierHeartbeatTimestamp sets the timestamp from the heartbeat response.
	SetVerifierHeartbeatTimestamp(ctx context.Context, timestamp int64)

	// SetVerifierHeartbeatSentChainHeads sets the block height sent in the heartbeat request for a chain.
	SetVerifierHeartbeatSentChainHeads(ctx context.Context, blockHeight uint64)

	// SetVerifierHeartbeatChainHeads sets the block height for a chain from the heartbeat response.
	SetVerifierHeartbeatChainHeads(ctx context.Context, blockHeight uint64)

	// SetVerifierHeartbeatScore sets the score for a chain from the heartbeat response.
	SetVerifierHeartbeatScore(ctx context.Context, score float64)
}

// ObservedHeartbeatClient wraps a HeartbeatClient with observability.
type ObservedHeartbeatClient struct {
	delegate   *HeartbeatClient
	verifierID string
	lggr       logger.Logger
	monitoring Monitoring
}

// NewObservedHeartbeatClient creates a new observed heartbeat client.
func NewObservedHeartbeatClient(
	delegate *HeartbeatClient,
	verifierID string,
	lggr logger.Logger,
	monitoring Monitoring,
) *ObservedHeartbeatClient {
	return &ObservedHeartbeatClient{
		delegate:   delegate,
		verifierID: verifierID,
		lggr:       lggr,
		monitoring: monitoring,
	}
}

// SendHeartbeat sends a heartbeat request with observability.
func (o *ObservedHeartbeatClient) SendHeartbeat(ctx context.Context, req *heartbeatpb.HeartbeatRequest, opts ...grpc.CallOption) (*heartbeatpb.HeartbeatResponse, error) {
	start := time.Now()

	resp, err := o.delegate.SendHeartbeat(ctx, req, opts...)

	duration := time.Since(start)

	metrics := o.monitoring.Metrics().With("verifier_id", o.verifierID)
	metrics.RecordHeartbeatDuration(ctx, duration)

	// Record what we're sending in the request. It will be used for monitoring of the lag.
	for chainSelector, blockHeight := range req.ChainDetails.BlockHeightsByChain {
		chainMetrics := metrics.With("chain_selector", fmt.Sprintf("%d", chainSelector))
		chainMetrics.SetVerifierHeartbeatSentChainHeads(ctx, blockHeight)
	}

	if err != nil {
		metrics.IncrementHeartbeatsFailed(ctx)
		o.lggr.Errorw("Heartbeat failed",
			"error", err,
			"duration", duration,
		)
		return nil, err
	}

	metrics.IncrementHeartbeatsSent(ctx)

	metrics.SetVerifierHeartbeatTimestamp(ctx, resp.Timestamp)

	// Record per-chain benchmarks from the response.
	for chainSelector, benchmark := range resp.ChainBenchmarks {
		chainMetrics := metrics.With("chain_selector", fmt.Sprintf("%d", chainSelector))
		chainMetrics.SetVerifierHeartbeatChainHeads(ctx, benchmark.BlockHeight)
		chainMetrics.SetVerifierHeartbeatScore(ctx, float64(benchmark.Score))
	}

	o.lggr.Debugw("Heartbeat succeeded",
		"duration", duration,
		"chainCount", len(req.ChainDetails.BlockHeightsByChain),
		"chainBenchmarkCount", len(resp.ChainBenchmarks),
	)

	return resp, nil
}

// Close closes the underlying heartbeat client.
func (o *ObservedHeartbeatClient) Close() error {
	return o.delegate.Close()
}
