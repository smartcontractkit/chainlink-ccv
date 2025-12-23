package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestSecureRecovery(t *testing.T) {
	t.Run("recovers from panic and returns generic error", func(t *testing.T) {
		// Setup
		gin.SetMode(gin.TestMode)
		lggr := logger.Test(t)

		router := gin.New()
		router.Use(SecureRecovery(lggr))

		// Create a handler that panics
		router.GET("/panic", func(c *gin.Context) {
			panic("something went wrong with sensitive data: password123")
		})

		w := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/panic", nil)
		require.NoError(t, err)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		body := w.Body.String()
		assert.Contains(t, body, "Internal server error")
		assert.Contains(t, body, `"success":false`)

		// Ensure no stack trace or sensitive data is exposed
		assert.NotContains(t, body, "panic")
		assert.NotContains(t, body, "password123")
		assert.NotContains(t, body, "goroutine")
		assert.NotContains(t, body, "runtime/")
	})

	t.Run("does not interfere with normal requests", func(t *testing.T) {
		// Setup
		gin.SetMode(gin.TestMode)
		lggr := logger.Test(t)

		router := gin.New()
		router.Use(SecureRecovery(lggr))

		// Create a normal handler
		router.GET("/normal", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"data":    "hello world",
			})
		})

		w := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/normal", nil)
		require.NoError(t, err)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "hello world")
		assert.Contains(t, w.Body.String(), `"success":true`)
	})

	t.Run("does not interfere with error responses", func(t *testing.T) {
		// Setup
		gin.SetMode(gin.TestMode)
		lggr := logger.Test(t)

		router := gin.New()
		router.Use(SecureRecovery(lggr))

		// Create a handler that returns an error (but doesn't panic)
		router.GET("/error", func(c *gin.Context) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Bad request - invalid parameter",
			})
		})

		w := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/error", nil)
		require.NoError(t, err)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, "Bad request - invalid parameter")
		assert.Contains(t, body, `"success":false`)
	})
}
