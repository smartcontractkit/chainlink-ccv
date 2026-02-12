package middleware

import (
	"context"
	"time"
)

// HTTPMetrics defines the interface for tracking HTTP request metrics.
// This interface is implemented by monitoring systems to record HTTP-related metrics.
type HTTPMetrics interface {
	// IncrementActiveRequestsCounter increments the active requests counter.
	IncrementActiveRequestsCounter(ctx context.Context)
	// IncrementHTTPRequestCounter increments the HTTP request counter.
	IncrementHTTPRequestCounter(ctx context.Context)
	// DecrementActiveRequestsCounter decrements the active requests counter.
	DecrementActiveRequestsCounter(ctx context.Context)
	// RecordHTTPRequestDuration records the HTTP request duration with path, method, and status.
	RecordHTTPRequestDuration(ctx context.Context, duration time.Duration, path, method string, status int)
}

// PathNormalizer is a function type that normalizes URL paths for metrics.
// It can be used to replace dynamic path segments (like IDs) with placeholders
// to avoid metric explosion. Returns the normalized path and a boolean indicating
// whether the endpoint should be tracked in metrics.
type PathNormalizer func(path string) (string, bool)

// NoOpPathNormalizer returns the path as-is without any normalization and always tracks it.
func NoOpPathNormalizer(path string) (string, bool) {
	return path, true
}
