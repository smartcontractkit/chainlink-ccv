package heartbeatclient

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	heartbeatpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/heartbeat/v1"
)

// HeartbeatSender defines the interface for sending heartbeats to the aggregator.
type HeartbeatSender interface {
	// SendHeartbeat sends chain status information to the aggregator.
	// Returns the aggregator's response containing benchmarks and timestamp.
	SendHeartbeat(ctx context.Context, blockHeightsByChain map[uint64]uint64) (HeartbeatResponse, error)
	// Close closes the heartbeat client connection.
	Close() error
}

// HeartbeatResponse contains the aggregator's response to a heartbeat.
type HeartbeatResponse struct {
	AggregatorID    string
	Timestamp       int64
	ChainBenchmarks map[uint64]ChainBenchmark
}

// ChainBenchmark contains benchmark information for a specific chain.
type ChainBenchmark struct {
	BlockHeight uint64
	Score       float32
}

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
func (o *ObservedHeartbeatClient) SendHeartbeat(ctx context.Context, blockHeightsByChain map[uint64]uint64) (HeartbeatResponse, error) {
	start := time.Now()

	// Build proto request
	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: time.Now().Unix(),
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: blockHeightsByChain,
		},
	}

	resp, err := o.delegate.SendHeartbeat(ctx, req)

	duration := time.Since(start)

	metrics := o.monitoring.Metrics().With("verifier_id", o.verifierID)
	metrics.RecordHeartbeatDuration(ctx, duration)

	// Record what we're sending in the request. It will be used for monitoring of the lag.
	for chainSelector, blockHeight := range blockHeightsByChain {
		chainMetrics := metrics.With("chain_selector", fmt.Sprintf("%d", chainSelector))
		chainMetrics.SetVerifierHeartbeatSentChainHeads(ctx, blockHeight)
	}

	if err != nil {
		metrics.IncrementHeartbeatsFailed(ctx)
		o.lggr.Errorw("Heartbeat failed",
			"error", err,
			"duration", duration,
		)
		return HeartbeatResponse{}, err
	}

	metrics.IncrementHeartbeatsSent(ctx)

	metrics.SetVerifierHeartbeatTimestamp(ctx, resp.Timestamp)

	// Convert proto response to domain response
	chainBenchmarks := make(map[uint64]ChainBenchmark, len(resp.ChainBenchmarks))
	for chainSelector, benchmark := range resp.ChainBenchmarks {
		chainBenchmarks[chainSelector] = ChainBenchmark{
			BlockHeight: benchmark.BlockHeight,
			Score:       benchmark.Score,
		}

		// Record metrics
		chainMetrics := metrics.With("chain_selector", fmt.Sprintf("%d", chainSelector))
		chainMetrics.SetVerifierHeartbeatChainHeads(ctx, benchmark.BlockHeight)
		chainMetrics.SetVerifierHeartbeatScore(ctx, float64(benchmark.Score))
	}

	o.lggr.Debugw("Heartbeat succeeded",
		"duration", duration,
		"chainCount", len(blockHeightsByChain),
		"chainBenchmarkCount", len(chainBenchmarks),
	)

	return HeartbeatResponse{
		AggregatorID:    resp.AggregatorId,
		Timestamp:       resp.Timestamp,
		ChainBenchmarks: chainBenchmarks,
	}, nil
}

// Close closes the underlying heartbeat client.
func (o *ObservedHeartbeatClient) Close() error {
	return o.delegate.Close()
}
