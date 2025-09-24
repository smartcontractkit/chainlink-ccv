package monitoring

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
)

var _ common.IndexerMetricLabeler = (*NoopIndexerMetricLabeler)(nil)

// NoopIndexerMetricLabeler provides a no-op implementation of IndexerMetricLabeler
// that doesn't actually record any metrics. Useful for testing or when monitoring is disabled.
type NoopIndexerMetricLabeler struct{}

// NewNoopIndexerMetricLabeler creates a new noop metric labeler.
func NewNoopIndexerMetricLabeler() common.IndexerMetricLabeler {
	return &NoopIndexerMetricLabeler{}
}

// With returns a new noop labeler with the given key-value pairs (no-op).
func (n *NoopIndexerMetricLabeler) With(keyValues ...string) common.IndexerMetricLabeler {
	return n
}

// All metric recording methods are no-ops.
func (n *NoopIndexerMetricLabeler) IncrementHTTPRequestCounter(ctx context.Context)         {}
func (n *NoopIndexerMetricLabeler) IncrementActiveRequestsCounter(ctx context.Context)      {}
func (n *NoopIndexerMetricLabeler) DecrementActiveRequestsCounter(ctx context.Context)      {}
func (n *NoopIndexerMetricLabeler) IncrementUniqueMessagesCounter(ctx context.Context)      {}
func (n *NoopIndexerMetricLabeler) IncrementVerificationRecordsCounter(ctx context.Context) {}
func (n *NoopIndexerMetricLabeler) RecordStorageQueryDuration(ctx context.Context, duration time.Duration) {
}

func (n *NoopIndexerMetricLabeler) RecordStorageWriteDuration(ctx context.Context, duration time.Duration) {
}
func (n *NoopIndexerMetricLabeler) RecordStorageInsertErrorsCounter(ctx context.Context) {}
func (n *NoopIndexerMetricLabeler) RecordVerificationRecordRequestDuration(ctx context.Context, duration time.Duration) {
}
func (n *NoopIndexerMetricLabeler) RecordScannerPollingErrorsCounter(ctx context.Context) {}
func (n *NoopIndexerMetricLabeler) RecordVerificationRecordChannelSizeGauge(ctx context.Context, size int64) {
}
func (n *NoopIndexerMetricLabeler) RecordActiveReadersGauge(ctx context.Context, count int64) {}
