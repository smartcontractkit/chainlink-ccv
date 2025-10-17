package monitoring

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

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

func (c *NoopAggregatorMetricLabeler) RecordDynamoDBReadCapacityUnits(ctx context.Context, units float64) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) RecordDynamoDBWriteCapacityUnits(ctx context.Context, units float64) {
	// No-op
}

func (c *NoopAggregatorMetricLabeler) RecordCapacity(capacity *types.ConsumedCapacity) {
	// No-op
}
