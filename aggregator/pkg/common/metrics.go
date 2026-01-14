package common

import (
	"context"
	"time"
)

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
	RecordAPIRequestDuration(ctx context.Context, duration time.Duration)
	// IncrementAPIRequestErrors increments the API request errors counter.
	IncrementAPIRequestErrors(ctx context.Context)
	// RecordMessageSinceNumberOfRecordsReturned records the number of records returned for a GetMessageSince request.
	RecordMessageSinceNumberOfRecordsReturned(ctx context.Context, count int)
	// IncrementPendingAggregationsChannelBuffer increments the pending aggregations channel buffer counter.
	IncrementPendingAggregationsChannelBuffer(ctx context.Context, count int)
	// DecrementPendingAggregationsChannelBuffer decrements the pending aggregations channel buffer counter.
	DecrementPendingAggregationsChannelBuffer(ctx context.Context, count int)
	// RecordStorageLatency records storage operation latency in milliseconds.
	RecordStorageLatency(ctx context.Context, duration time.Duration)
	// IncrementStorageError increments the storage error counter.
	IncrementStorageError(ctx context.Context)
	// RecordTimeToAggregation records the time taken to complete an aggregation.
	RecordTimeToAggregation(ctx context.Context, duration time.Duration)
	// SetOrphanBacklog sets the gauge for non-expired orphan records (recovery queue).
	SetOrphanBacklog(ctx context.Context, count int)
	// SetOrphanExpiredBacklog sets the gauge for expired orphan records (pending cleanup).
	SetOrphanExpiredBacklog(ctx context.Context, count int)
	// RecordOrphanRecoveryDuration records the duration of an orphan recovery scan.
	// The histogram count can be used to determine the number of runs.
	RecordOrphanRecoveryDuration(ctx context.Context, duration time.Duration)
	// IncrementOrphanRecoveryErrors increments the counter for errors during orphan recovery.
	IncrementOrphanRecoveryErrors(ctx context.Context)
	// IncrementPanics increments the counter for panics recovered by background workers.
	IncrementPanics(ctx context.Context)
	// SetVerifierHeartbeatScore sets the adaptive heartbeat score gauge for a verifier on a specific chain.
	SetVerifierHeartbeatScore(ctx context.Context, score float64)
	// SetVerifierLastHeartbeatTimestamp sets the timestamp gauge of the last heartbeat from a verifier.
	SetVerifierLastHeartbeatTimestamp(ctx context.Context, timestamp int64)
	// IncrementVerifierHeartbeatsTotal increments the total number of heartbeats received.
	IncrementVerifierHeartbeatsTotal(ctx context.Context)
	// SetVerifierHeartbeatChainHeads sets the block height gauge for a verifier on a specific chain.
	SetVerifierHeartbeatChainHeads(ctx context.Context, blockHeight uint64)
}
