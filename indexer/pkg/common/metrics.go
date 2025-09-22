package common

import (
	"context"
	"time"
)

type IndexerMonitoring interface {
	Metrics() IndexerMetricLabeler
}

type IndexerMetricLabeler interface {
	With(keyValues ...string) IndexerMetricLabeler
	IncrementHTTPRequestCounter(ctx context.Context)
	IncrementActiveRequestsCounter(ctx context.Context)
	DecrementActiveRequestsCounter(ctx context.Context)
	IncrementUniqueMessagesCounter(ctx context.Context)
	IncrementVerificationRecordsCounter(ctx context.Context)
	RecordStorageQueryDuration(ctx context.Context, duration time.Duration)
	RecordStorageWriteDuration(ctx context.Context, duration time.Duration)
	RecordStorageInsertErrorsCounter(ctx context.Context)
	RecordVerificationRecordRequestDuration(ctx context.Context, duration time.Duration)
	RecordScannerPollingErrorsCounter(ctx context.Context)
	RecordVerificationRecordChannelSizeGauge(ctx context.Context, size int64)
	RecordActiveReadersGauge(ctx context.Context, count int64)
}
