package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ActiveRequestsMiddleware creates a gin middleware that tracks active requests.
func ActiveRequestsMiddleware(monitoring common.IndexerMonitoring, lggr logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the metrics labeler with request-specific labels
		metrics := monitoring.Metrics().With(
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", "pending", // Will be updated when request completes
		)

		// Increment active requests counter
		metrics.IncrementActiveRequestsCounter(c.Request.Context())

		// Increment HTTP request counter
		metrics.IncrementHTTPRequestCounter(c.Request.Context())

		// Record start time for potential duration tracking
		start := time.Now()

		// Process the request
		c.Next()

		// Update status based on response
		status := "success"
		if c.Writer.Status() >= 400 {
			status = "error"
		}

		// Get updated metrics with final status
		finalMetrics := monitoring.Metrics().With(
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", status,
			"status_code", http.StatusText(c.Writer.Status()),
		)

		// Decrement active requests counter
		finalMetrics.DecrementActiveRequestsCounter(c.Request.Context())

		// Log request completion with duration
		duration := time.Since(start)
		lggr.Debugw("Request completed",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"duration_ms", duration.Milliseconds(),
		)
	}
}
