package heartbeatclient

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	heartbeatpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/heartbeat/v1"
)

// ObservedHeartbeatClient wraps a HeartbeatClient with observability.
type ObservedHeartbeatClient struct {
	delegate   *HeartbeatClient
	verifierID string
	lggr       logger.Logger
	monitoring verifier.Monitoring
}

// NewObservedHeartbeatClient creates a new observed heartbeat client.
func NewObservedHeartbeatClient(
	delegate *HeartbeatClient,
	verifierID string,
	lggr logger.Logger,
	monitoring verifier.Monitoring,
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
