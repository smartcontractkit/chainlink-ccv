package middleware

import (
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// SecureRecovery returns a middleware that recovers from panics and returns a generic error response
// without exposing internal details. The full error and stack trace are logged for debugging.
func SecureRecovery(lggr logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				stack := debug.Stack()

				// Log the full error with stack trace for internal debugging
				lggr.Errorw("Panic recovered",
					"error", err,
					"path", c.Request.URL.Path,
					"method", c.Request.Method,
					"stack", string(stack),
				)

				c.JSON(http.StatusInternalServerError, gin.H{
					"success": false,
					"error":   "Internal server error",
				})

				c.Abort()
			}
		}()
		c.Next()
	}
}
