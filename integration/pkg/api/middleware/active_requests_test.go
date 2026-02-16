package middleware

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// mockHTTPMetrics is a simple mock implementation for testing.
type mockHTTPMetrics struct {
	activeRequestsInc      int
	activeRequestsDec      int
	httpRequestCounter     int
	requestDurationRecords []requestDurationRecord
}

type requestDurationRecord struct {
	duration time.Duration
	path     string
	method   string
	status   int
}

func (m *mockHTTPMetrics) IncrementActiveRequestsCounter(ctx context.Context) {
	m.activeRequestsInc++
}

func (m *mockHTTPMetrics) DecrementActiveRequestsCounter(ctx context.Context) {
	m.activeRequestsDec++
}

func (m *mockHTTPMetrics) RecordHTTPRequestDuration(ctx context.Context, duration time.Duration, path, method string, status int) {
	m.requestDurationRecords = append(m.requestDurationRecords, requestDurationRecord{
		duration: duration,
		path:     path,
		method:   method,
		status:   status,
	})
}

// TestActiveRequestsMiddleware_WithPathNormalizer verifies the middleware
// uses the provided path normalizer function.
func TestActiveRequestsMiddleware_WithPathNormalizer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)
	metrics := &mockHTTPMetrics{}

	// Custom path normalizer that replaces IDs with placeholders
	normalizer := func(path string) (string, bool) {
		if path == "/users/123" {
			return "/users/:id", true
		}
		return path, true
	}

	r := gin.New()
	r.Use(ActiveRequestsMiddleware(metrics, normalizer, lggr))
	r.GET("/users/:id", func(c *gin.Context) {
		c.Status(200)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/users/123", nil)
	r.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
	require.Len(t, metrics.requestDurationRecords, 1)
	// Verify the normalized path is used in metrics
	require.Equal(t, "/users/:id", metrics.requestDurationRecords[0].path)
	require.Equal(t, "GET", metrics.requestDurationRecords[0].method)
	require.Equal(t, 200, metrics.requestDurationRecords[0].status)
}

// TestActiveRequestsMiddleware_SkipsTrackingWhenNormalizerReturnsFalse verifies
// that duration metrics are not recorded when the path normalizer returns false.
func TestActiveRequestsMiddleware_SkipsTrackingWhenNormalizerReturnsFalse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)
	metrics := &mockHTTPMetrics{}

	// Custom path normalizer that returns false for certain paths
	normalizer := func(path string) (string, bool) {
		if path == "/health" || path == "/ready" {
			return path, false // Don't track health/ready endpoints
		}
		return path, true
	}

	r := gin.New()
	r.Use(ActiveRequestsMiddleware(metrics, normalizer, lggr))
	r.GET("/health", func(c *gin.Context) {
		c.Status(200)
	})
	r.GET("/api/users", func(c *gin.Context) {
		c.Status(200)
	})

	// Test health endpoint - should not be tracked
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/health", nil)
	r.ServeHTTP(rec1, req1)

	require.Equal(t, 200, rec1.Code)
	require.Equal(t, 1, metrics.activeRequestsInc)
	require.Equal(t, 1, metrics.activeRequestsDec)
	require.Equal(t, 1, metrics.httpRequestCounter)
	require.Len(t, metrics.requestDurationRecords, 0, "health endpoint should not be tracked")

	// Test regular endpoint - should be tracked
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/api/users", nil)
	r.ServeHTTP(rec2, req2)

	require.Equal(t, 200, rec2.Code)
	require.Equal(t, 2, metrics.activeRequestsInc)
	require.Equal(t, 2, metrics.activeRequestsDec)
	require.Equal(t, 2, metrics.httpRequestCounter)
	require.Len(t, metrics.requestDurationRecords, 1, "api endpoint should be tracked")
	require.Equal(t, "/api/users", metrics.requestDurationRecords[0].path)
}
