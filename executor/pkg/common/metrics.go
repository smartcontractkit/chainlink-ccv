package common

import (
	"context"
	"time"
)

// ExecutorMonitoring provides all core monitoring functionality for the indexer. Also can be implemented as a no-op.
type ExecutorMonitoring interface {
	// Metrics returns the metrics labeler for the indexer.
	Metrics() ExecutorMetricLabeler
}

// ExecutorMetricLabeler provides all metric recording functionality for the indexer.
type ExecutorMetricLabeler interface {
	// With returns a new metrics labeler with the given key-value pairs.
	With(keyValues ...string) ExecutorMetricLabeler
	// RecordMessageExecutionLatency increments the HTTP request counter.
	RecordMessageExecutionLatency(ctx context.Context, duration time.Duration)
	// IncrementMessagesProcessed increments the active requests counter.
	IncrementMessagesProcessed(ctx context.Context)
	// IncrementMessagesProcessingFailed decrements the active requests counter.
	IncrementMessagesProcessingFailed(ctx context.Context)
}
