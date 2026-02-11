package middleware

import (
	"context"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	sharedmiddleware "github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/middleware"
)

// IndexerMetricsAdapter adapts IndexerMonitoring to the HTTPMetrics interface.
type IndexerMetricsAdapter struct {
	monitoring common.IndexerMonitoring
}

// NewIndexerMetricsAdapter creates a new adapter that wraps IndexerMonitoring.
func NewIndexerMetricsAdapter(monitoring common.IndexerMonitoring) sharedmiddleware.HTTPMetrics {
	return &IndexerMetricsAdapter{monitoring: monitoring}
}

// IncrementActiveRequestsCounter implements HTTPMetrics.
func (a *IndexerMetricsAdapter) IncrementActiveRequestsCounter(ctx context.Context) {
	a.monitoring.Metrics().IncrementActiveRequestsCounter(ctx)
}

// IncrementHTTPRequestCounter implements HTTPMetrics.
func (a *IndexerMetricsAdapter) IncrementHTTPRequestCounter(ctx context.Context) {
	a.monitoring.Metrics().IncrementHTTPRequestCounter(ctx)
}

// DecrementActiveRequestsCounter implements HTTPMetrics.
func (a *IndexerMetricsAdapter) DecrementActiveRequestsCounter(ctx context.Context) {
	a.monitoring.Metrics().DecrementActiveRequestsCounter(ctx)
}

// RecordHTTPRequestDuration implements HTTPMetrics.
func (a *IndexerMetricsAdapter) RecordHTTPRequestDuration(ctx context.Context, duration time.Duration, path, method string, status int) {
	a.monitoring.Metrics().RecordHTTPRequestDuration(ctx, duration, path, method, status)
}

// RemoveMessageIDFromPath normalizes verifierresults paths by replacing message IDs with a placeholder.
func RemoveMessageIDFromPath(path string) string {
	if strings.Contains(path, "/verifierresults/") {
		// Normalize to a canonical path with a placeholder for the message ID.
		return "/verifierresults/:messageID"
	}

	return path
}
