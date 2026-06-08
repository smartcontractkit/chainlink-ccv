package middleware

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ActiveRequestsMiddleware creates a gin middleware that tracks active requests.
// It uses the provided HTTPMetrics to record metrics about HTTP requests and
func ActiveRequestsMiddleware(metrics HTTPMetrics, lggr logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Increment active requests counter
		metrics.IncrementActiveRequestsCounter(c.Request.Context())

		// Record start time for potential duration tracking
		start := time.Now()

		// Process the request
		c.Next()

		// Decrement active requests counter
		metrics.DecrementActiveRequestsCounter(c.Request.Context())

		// Log request completion with duration
		duration := time.Since(start)

		lggr.Debugw("Request completed",
			"method", c.Request.Method,
			"path", c.FullPath(),
			"status", c.Writer.Status(),
			"duration_ms", duration.Milliseconds(),
		)

		// don't track unknown paths
		if c.FullPath() == "" {
			return
		}
		metrics.RecordHTTPRequestDuration(
			c.Request.Context(),
			duration,
			c.FullPath(),
			c.Request.Method,
			c.Writer.Status(),
		)
	}
}
