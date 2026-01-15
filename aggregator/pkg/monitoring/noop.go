package monitoring

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
)

type NoopAggregatorMonitoring struct{}

func NewNoopAggregatorMonitoring() *NoopAggregatorMonitoring {
	return &NoopAggregatorMonitoring{}
}

func (m *NoopAggregatorMonitoring) Metrics() common.AggregatorMetricLabeler {
	return NewNoopAggregatorMetricLabeler()
}

type NoopAggregatorMetricLabeler struct{}

func NewNoopAggregatorMetricLabeler() *NoopAggregatorMetricLabeler {
	return &NoopAggregatorMetricLabeler{}
}

func (c *NoopAggregatorMetricLabeler) With(...string) common.AggregatorMetricLabeler {
	return c
}

func (c *NoopAggregatorMetricLabeler) IncrementActiveRequestsCounter(ctx context.Context) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) DecrementActiveRequestsCounter(ctx context.Context) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) IncrementCompletedAggregations(ctx context.Context) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) RecordAPIRequestDuration(ctx context.Context, duration time.Duration) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) IncrementAPIRequestErrors(ctx context.Context) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) RecordMessageSinceNumberOfRecordsReturned(ctx context.Context, count int) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) IncrementPendingAggregationsChannelBuffer(ctx context.Context, count int) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) DecrementPendingAggregationsChannelBuffer(ctx context.Context, count int) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) RecordStorageLatency(ctx context.Context, duration time.Duration) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) IncrementStorageError(ctx context.Context) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) RecordTimeToAggregation(ctx context.Context, duration time.Duration) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) SetOrphanBacklog(ctx context.Context, count int) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) SetOrphanExpiredBacklog(ctx context.Context, count int) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) RecordOrphanRecoveryDuration(ctx context.Context, duration time.Duration) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) IncrementOrphanRecoveryErrors(ctx context.Context) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) IncrementPanics(ctx context.Context) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) SetVerifierHeartbeatScore(ctx context.Context, score float64) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) SetVerifierLastHeartbeatTimestamp(ctx context.Context, timestamp int64) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) IncrementVerifierHeartbeatsTotal(ctx context.Context) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) SetVerifierHeartbeatChainHeads(ctx context.Context, blockHeight uint64) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) IncrementVerificationsTotal(ctx context.Context) {
	// No-op
}
