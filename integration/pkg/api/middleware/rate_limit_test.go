package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// TestRateLimit_HandlerEnabledAndDisabled checks that the RateLimit middleware
// behaves as a no-op when disabled and allows requests when enabled (under the limit).
func TestRateLimit_HandlerEnabledAndDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)

	// Disabled case: middleware should be no-op and allow request through
	cfgOff := &config.Config{API: config.APIConfig{RateLimit: config.RateLimitConfig{Enabled: false}}}
	r := gin.New()
	rateLimitCfgOff := RateLimitConfig{
		Enabled: cfgOff.API.RateLimit.Enabled,
		Period:  0, // Will use defaults
		Limit:   0, // Will use defaults
	}
	r.Use(RateLimit(lggr, rateLimitCfgOff))
	r.GET("/", func(c *gin.Context) { c.String(200, "ok") })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	r.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	// Enabled case: should also allow a request under rate limit
	cfgOn := &config.Config{API: config.APIConfig{RateLimit: config.RateLimitConfig{Enabled: true}}}
	r2 := gin.New()
	rateLimitCfgOn := RateLimitConfig{
		Enabled: cfgOn.API.RateLimit.Enabled,
		Period:  0, // Will use defaults
		Limit:   0, // Will use defaults
	}
	r2.Use(RateLimit(lggr, rateLimitCfgOn))
	r2.GET("/", func(c *gin.Context) { c.String(200, "ok") })

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/", nil)
	r2.ServeHTTP(rec2, req2)
	require.Equal(t, 200, rec2.Code)
}

func TestRateLimit_Disabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)

	cfg := RateLimitConfig{
		Enabled: false,
		Period:  1 * time.Second,
		Limit:   5,
	}

	router := gin.New()
	router.Use(RateLimit(lggr, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Should allow unlimited requests when disabled
	for i := range 20 {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed when rate limiting is disabled", i)
	}
}

func TestRateLimit_Enabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)

	cfg := RateLimitConfig{
		Enabled: true,
		Period:  1 * time.Second,
		Limit:   5,
	}

	router := gin.New()
	router.Use(RateLimit(lggr, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// First 5 requests should succeed
	for i := range 5 {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i)
	}

	// 6th request should be rate limited
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "Request should be rate limited")

	// After waiting for the period, requests should succeed again
	time.Sleep(1100 * time.Millisecond)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "Request should succeed after period expires")
}

func TestRateLimit_UsesDefaults(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)

	cfg := RateLimitConfig{
		Enabled: true,
		Period:  0, // Should use default
		Limit:   0, // Should use default
	}

	router := gin.New()
	router.Use(RateLimit(lggr, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Should use DefaultRateLimit (10 requests per second)
	// First 10 requests should succeed
	for i := range 10 {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "Request %d should succeed with default limit", i)
	}

	// 11th request should be rate limited
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "Request should be rate limited with default limit")
}

func TestRateLimit_PartialDefaults(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lggr := logger.Test(t)

	t.Run("Only Period is zero", func(t *testing.T) {
		cfg := RateLimitConfig{
			Enabled: true,
			Period:  0, // Should use default (1 second)
			Limit:   3, // Custom limit
		}

		router := gin.New()
		router.Use(RateLimit(lggr, cfg))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		// First 3 requests should succeed
		for i := range 3 {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i)
		}

		// 4th request should be rate limited
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code, "Request should be rate limited")
	})

	t.Run("Only Limit is zero", func(t *testing.T) {
		cfg := RateLimitConfig{
			Enabled: true,
			Period:  2 * time.Second, // Custom period
			Limit:   0,               // Should use default (10)
		}

		router := gin.New()
		router.Use(RateLimit(lggr, cfg))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		// First 10 requests should succeed
		for i := range 10 {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i)
		}

		// 11th request should be rate limited
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code, "Request should be rate limited")
	})
}
