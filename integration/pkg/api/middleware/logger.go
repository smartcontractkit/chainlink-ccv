package middleware

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// GinLogger returns a gin middleware that logs HTTP requests using the provided logger.
func GinLogger(lggr logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		if raw := c.Request.URL.RawQuery; raw != "" {
			path = path + "?" + raw
		}

		c.Next()

		fields := []any{
			"method", c.Request.Method,
			"path", path,
			"status", c.Writer.Status(),
			"latency", time.Since(start),
			"clientIP", c.ClientIP(),
		}
		if errMsg := c.Errors.ByType(gin.ErrorTypePrivate).String(); errMsg != "" {
			fields = append(fields, "errors", errMsg)
		}
		lggr.Infow("Request", fields...)
	}
}
