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

func (m *mockHTTPMetrics) IncrementHTTPRequestCounter(ctx context.Context) {
	m.httpRequestCounter++
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

// TestActiveRequestsMiddleware_BasicFunctionality verifies the middleware
// correctly tracks request metrics.
func TestActiveRequestsMiddleware_BasicFunctionality(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)
	metrics := &mockHTTPMetrics{}

	r := gin.New()
	r.Use(ActiveRequestsMiddleware(metrics, NoOpPathNormalizer, lggr))
	r.GET("/test", func(c *gin.Context) {
		c.Status(200)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
	require.Equal(t, 1, metrics.activeRequestsInc)
	require.Equal(t, 1, metrics.activeRequestsDec)
	require.Equal(t, 1, metrics.httpRequestCounter)
	require.Len(t, metrics.requestDurationRecords, 1)
	require.Equal(t, "/test", metrics.requestDurationRecords[0].path)
	require.Equal(t, "GET", metrics.requestDurationRecords[0].method)
	require.Equal(t, 200, metrics.requestDurationRecords[0].status)
}

// TestActiveRequestsMiddleware_WithPathNormalizer verifies the middleware
// uses the provided path normalizer function.
func TestActiveRequestsMiddleware_WithPathNormalizer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)
	metrics := &mockHTTPMetrics{}

	// Custom path normalizer that replaces IDs with placeholders
	normalizer := func(path string) string {
		if path == "/users/123" {
			return "/users/:id"
		}
		return path
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

// TestActiveRequestsMiddleware_DecrementsOnError verifies the middleware
// decrements active requests counter even when the handler returns an error.
func TestActiveRequestsMiddleware_DecrementsOnError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)
	metrics := &mockHTTPMetrics{}

	r := gin.New()
	r.Use(ActiveRequestsMiddleware(metrics, NoOpPathNormalizer, lggr))
	r.GET("/error", func(c *gin.Context) {
		c.Status(500)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/error", nil)
	r.ServeHTTP(rec, req)

	require.Equal(t, 500, rec.Code)
	require.Equal(t, 1, metrics.activeRequestsInc)
	require.Equal(t, 1, metrics.activeRequestsDec)
	require.Equal(t, 1, metrics.httpRequestCounter)
	require.Len(t, metrics.requestDurationRecords, 1)
	require.Equal(t, 500, metrics.requestDurationRecords[0].status)
}
