package common

import (
	"context"
	"time"

	commonmetrics "github.com/smartcontractkit/chainlink-ccv/common/metrics"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// IndexerMonitoring provides all core monitoring functionality for the indexer. Also can be implemented as a no-op.
// ServiceMetrics is embedded so that common service-level metrics (e.g. ccip_service_started)
// and any future ones are part of this interface without changing it.
type IndexerMonitoring interface {
	// Metrics returns the metrics labeler for the indexer.
	Metrics() IndexerMetricLabeler
	// Logger returns the logger for the indexer.
	Logger() logger.Logger
	commonmetrics.ServiceMetrics
}

// IndexerMetricLabeler provides all metric recording functionality for the indexer.
type IndexerMetricLabeler interface {
	// With returns a new metrics labeler with the given key-value pairs.
	With(keyValues ...string) IndexerMetricLabeler
	// IncrementActiveRequestsCounter increments the active requests counter.
	IncrementActiveRequestsCounter(ctx context.Context)
	// DecrementActiveRequestsCounter decrements the active requests counter.
	DecrementActiveRequestsCounter(ctx context.Context)
	// RecordHTTPRequestDuration records the HTTP request duration.
	RecordHTTPRequestDuration(ctx context.Context, duration time.Duration, path, method string, status int)
	// IncrementVerificationRecordsCounter increments the verification records counter.
	IncrementVerificationRecordsCounter(ctx context.Context)
	// RecordStorageLatency records storage operation latency.
	RecordStorageLatency(ctx context.Context, operation string, duration time.Duration, errored bool)
	// IncrementStorageError increments the storage error counter.
	IncrementStorageError(ctx context.Context, operation string)
	// RecordScannerPollingErrorsCounter records the scanner polling errors counter.
	RecordScannerPollingErrorsCounter(ctx context.Context)
	// RecordVerificationRecordChannelSizeGauge records the verification record channel size gauge.
	RecordVerificationRecordChannelSizeGauge(ctx context.Context, size int64)
	// RecordActiveReadersGauge records the active readers gauge.
	RecordActiveReadersGauge(ctx context.Context, count int64)
	// RecordIndexerMessageDiscoveryLatency records the latency between message discovery and processing.
	RecordIndexerMessageDiscoveryLatency(ctx context.Context, latency time.Duration)
	// RecordTimeToIndex records the total time between aggregation and indexing.
	RecordTimeToIndex(ctx context.Context, latency time.Duration, discoveryType string)
	// RecordCircuitBreakerStatus records the status of the circuit breaker.
	RecordCircuitBreakerStatus(ctx context.Context, status bool)
	// RecordGRPCPayloadSize records the gRPC wire-level payload size in bytes.
	// target identifies the remote gRPC server (DiscoveryConfig.Label() or VerifierConfig.Label()).
	// direction is "recv" for received payloads, "send" for sent payloads.
	RecordGRPCPayloadSize(ctx context.Context, target, method, direction string, sizeBytes int)
	// IncrementGRPCErrors increments the counter for gRPC errors by status code.
	// target identifies the remote gRPC server (DiscoveryConfig.Label() or VerifierConfig.Label()).
	// code should be the gRPC status code string (e.g. "ResourceExhausted", "Internal").
	IncrementGRPCErrors(ctx context.Context, target, code, method string)
}
