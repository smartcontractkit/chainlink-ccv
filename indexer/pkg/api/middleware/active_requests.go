package middleware

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ActiveRequestsMiddleware creates a gin middleware that tracks active requests.
func ActiveRequestsMiddleware(monitoring common.IndexerMonitoring, lggr logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Increment active requests counter
		monitoring.Metrics().IncrementActiveRequestsCounter(c.Request.Context())

		// Increment HTTP request counter
		monitoring.Metrics().IncrementHTTPRequestCounter(c.Request.Context())

		// Record start time for potential duration tracking
		start := time.Now()

		// Process the request
		c.Next()

		// Decrement active requests counter
		monitoring.Metrics().DecrementActiveRequestsCounter(c.Request.Context())

		// Log request completion with duration
		duration := time.Since(start)

		monitoring.Metrics().RecordHTTPRequestDuration(c.Request.Context(), duration, removeMessageIDFromPath(c.Request.URL.Path), c.Request.Method, c.Writer.Status())
		lggr.Debugw("Request completed",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"duration_ms", duration.Milliseconds(),
		)
	}
}

func removeMessageIDFromPath(path string) string {
	if strings.Contains(path, "/verifierresults/") {
		parts := strings.Split(path, "/")[0:3]
		parts = append(parts, ":messageID")
		return strings.Join(parts, "/")
	}

	return path
}
