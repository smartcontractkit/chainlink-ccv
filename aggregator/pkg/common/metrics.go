package common

import "context"

type AggregatorMonitoring interface {
	Metrics() AggregatorMetricLabeler
}

type AggregatorMetricLabeler interface {
	With(keyValues ...string) AggregatorMetricLabeler
	IncrementActiveRequestsCounter(ctx context.Context)
	DecrementActiveRequestsCounter(ctx context.Context)
	IncrementCompletedAggregations(ctx context.Context)
	RecordAPIRequestDuration(ctx context.Context, durationMs int64)
	IncrementAPIRequestErrors(ctx context.Context)
	GetMessageSinceNumberOfRecordsReturned(ctx context.Context, count int)
	IncrementPendingAggregationsChannelBuffer(ctx context.Context, count int)
	DecrementPendingAggregationsChannelBuffer(ctx context.Context, count int)
	RecordStorageLatency(ctx context.Context, latencyMs int64)
	IncrementStorageError(ctx context.Context)
}
