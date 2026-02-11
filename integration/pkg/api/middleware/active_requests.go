package middleware

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ActiveRequestsMiddleware creates a gin middleware that tracks active requests.
// It uses the provided HTTPMetrics to record metrics about HTTP requests and
// applies the PathNormalizer to normalize paths before recording metrics.
func ActiveRequestsMiddleware(metrics HTTPMetrics, pathNormalizer PathNormalizer, lggr logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Increment active requests counter
		metrics.IncrementActiveRequestsCounter(c.Request.Context())

		// Increment HTTP request counter
		metrics.IncrementHTTPRequestCounter(c.Request.Context())

		// Record start time for potential duration tracking
		start := time.Now()

		// Process the request
		c.Next()

		// Decrement active requests counter
		metrics.DecrementActiveRequestsCounter(c.Request.Context())

		// Log request completion with duration
		duration := time.Since(start)

		// Normalize the path using the provided function
		normalizedPath := pathNormalizer(c.Request.URL.Path)

		metrics.RecordHTTPRequestDuration(c.Request.Context(), duration, normalizedPath, c.Request.Method, c.Writer.Status())
		lggr.Debugw("Request completed",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"duration_ms", duration.Milliseconds(),
		)
	}
}
