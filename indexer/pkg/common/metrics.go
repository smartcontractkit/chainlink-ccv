package common

import (
	"context"
	"time"
)

// IndexerMonitoring provides all core monitoring functionality for the indexer. Also can be implemented as a no-op.
type IndexerMonitoring interface {
	// Metrics returns the metrics labeler for the indexer.
	Metrics() IndexerMetricLabeler
}

// IndexerMetricLabeler provides all metric recording functionality for the indexer.
type IndexerMetricLabeler interface {
	// With returns a new metrics labeler with the given key-value pairs.
	With(keyValues ...string) IndexerMetricLabeler
	// IncrementHTTPRequestCounter increments the HTTP request counter.
	IncrementHTTPRequestCounter(ctx context.Context)
	// IncrementActiveRequestsCounter increments the active requests counter.
	IncrementActiveRequestsCounter(ctx context.Context)
	// DecrementActiveRequestsCounter decrements the active requests counter.
	DecrementActiveRequestsCounter(ctx context.Context)
	// RecordHTTPRequestDuration records the HTTP request duration.
	RecordHTTPRequestDuration(ctx context.Context, duration time.Duration, path, method string, status int)
	// IncrementUniqueMessagesCounter increments the unique messages counter.
	IncrementUniqueMessagesCounter(ctx context.Context)
	// IncrementVerificationRecordsCounter increments the verification records counter.
	IncrementVerificationRecordsCounter(ctx context.Context)
	// RecordStorageQueryDuration records the storage query duration.
	RecordStorageQueryDuration(ctx context.Context, duration time.Duration)
	// RecordStorageWriteDuration records the storage write duration.
	RecordStorageWriteDuration(ctx context.Context, duration time.Duration)
	// RecordStorageInsertErrorsCounter records the storage insert errors counter.
	RecordStorageInsertErrorsCounter(ctx context.Context)
	// RecordScannerPollingErrorsCounter records the scanner polling errors counter.
	RecordScannerPollingErrorsCounter(ctx context.Context)
	// RecordVerificationRecordChannelSizeGauge records the verification record channel size gauge.
	RecordVerificationRecordChannelSizeGauge(ctx context.Context, size int64)
	// RecordActiveReadersGauge records the active readers gauge.
	RecordActiveReadersGauge(ctx context.Context, count int64)
}
