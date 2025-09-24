package common

import "context"

// AggregatorMonitoring provides access to aggregator monitoring capabilities.
type AggregatorMonitoring interface {
	// Metrics returns an AggregatorMetricLabeler for recording metrics.
	Metrics() AggregatorMetricLabeler
}

// AggregatorMetricLabeler provides methods for recording various aggregator metrics.
type AggregatorMetricLabeler interface {
	// With returns a new AggregatorMetricLabeler with additional key-value labels.
	With(keyValues ...string) AggregatorMetricLabeler
	// IncrementActiveRequestsCounter increments the active requests counter.
	IncrementActiveRequestsCounter(ctx context.Context)
	// DecrementActiveRequestsCounter decrements the active requests counter.
	DecrementActiveRequestsCounter(ctx context.Context)
	// IncrementCompletedAggregations increments the completed aggregations counter.
	IncrementCompletedAggregations(ctx context.Context)
	// RecordAPIRequestDuration records the duration of an API request in milliseconds.
	RecordAPIRequestDuration(ctx context.Context, durationMs int64)
	// IncrementAPIRequestErrors increments the API request errors counter.
	IncrementAPIRequestErrors(ctx context.Context)
	// RecordMessageSinceNumberOfRecordsReturned records the number of records returned for a GetMessageSince request.
	RecordMessageSinceNumberOfRecordsReturned(ctx context.Context, count int)
	// IncrementPendingAggregationsChannelBuffer increments the pending aggregations channel buffer counter.
	IncrementPendingAggregationsChannelBuffer(ctx context.Context, count int)
	// DecrementPendingAggregationsChannelBuffer decrements the pending aggregations channel buffer counter.
	DecrementPendingAggregationsChannelBuffer(ctx context.Context, count int)
	// RecordStorageLatency records storage operation latency in milliseconds.
	RecordStorageLatency(ctx context.Context, latencyMs int64)
	// IncrementStorageError increments the storage error counter.
	IncrementStorageError(ctx context.Context)
}
