package verifier

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
)

// heartbeatMonitoringAdapter adapts verifier.Monitoring to heartbeatclient.Monitoring.
// This allows the reusable heartbeat client to work with verifier-specific monitoring.
type heartbeatMonitoringAdapter struct {
	monitoring Monitoring
}

// NewHeartbeatMonitoringAdapter creates an adapter that allows verifier.Monitoring
// to be used with the heartbeat client's observability layer.
func NewHeartbeatMonitoringAdapter(monitoring Monitoring) heartbeatclient.Monitoring {
	return &heartbeatMonitoringAdapter{monitoring: monitoring}
}

func (a *heartbeatMonitoringAdapter) Metrics() heartbeatclient.MetricLabeler {
	return &heartbeatMetricLabelerAdapter{labeler: a.monitoring.Metrics()}
}

// heartbeatMetricLabelerAdapter adapts verifier.MetricLabeler to heartbeatclient.MetricLabeler.
type heartbeatMetricLabelerAdapter struct {
	labeler MetricLabeler
}

func (a *heartbeatMetricLabelerAdapter) With(keyValues ...string) heartbeatclient.MetricLabeler {
	return &heartbeatMetricLabelerAdapter{labeler: a.labeler.With(keyValues...)}
}

func (a *heartbeatMetricLabelerAdapter) RecordHeartbeatDuration(ctx context.Context, duration time.Duration) {
	a.labeler.RecordHeartbeatDuration(ctx, duration)
}

func (a *heartbeatMetricLabelerAdapter) IncrementHeartbeatsSent(ctx context.Context) {
	a.labeler.IncrementHeartbeatsSent(ctx)
}

func (a *heartbeatMetricLabelerAdapter) IncrementHeartbeatsFailed(ctx context.Context) {
	a.labeler.IncrementHeartbeatsFailed(ctx)
}

func (a *heartbeatMetricLabelerAdapter) SetVerifierHeartbeatTimestamp(ctx context.Context, timestamp int64) {
	a.labeler.SetVerifierHeartbeatTimestamp(ctx, timestamp)
}

func (a *heartbeatMetricLabelerAdapter) SetVerifierHeartbeatSentChainHeads(ctx context.Context, blockHeight uint64) {
	a.labeler.SetVerifierHeartbeatSentChainHeads(ctx, blockHeight)
}

func (a *heartbeatMetricLabelerAdapter) SetVerifierHeartbeatChainHeads(ctx context.Context, blockHeight uint64) {
	a.labeler.SetVerifierHeartbeatChainHeads(ctx, blockHeight)
}

func (a *heartbeatMetricLabelerAdapter) SetVerifierHeartbeatScore(ctx context.Context, score float64) {
	a.labeler.SetVerifierHeartbeatScore(ctx, score)
}
