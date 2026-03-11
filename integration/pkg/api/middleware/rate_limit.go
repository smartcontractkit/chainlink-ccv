package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
)

var DefaultRateLimit = limiter.Rate{
	Period: 1 * time.Second,
	Limit:  10,
}

// RateLimitConfig provides configuration for rate limiting.
type RateLimitConfig struct {
	// Enabled enables the rate limiting middleware.
	Enabled bool
	// Period defines the time window for rate limiting (e.g., 1 second).
	// If set to 0, defaults to DefaultRateLimit.Period.
	Period time.Duration
	// Limit defines the maximum number of requests allowed in the Period.
	// If set to 0, defaults to DefaultRateLimit.Limit.
	Limit int64
}

// RateLimit creates a rate limiting middleware for Gin.
// If rate limiting is disabled, it returns a no-op middleware.
// If Period or Limit is 0, it falls back to DefaultRateLimit values.
func RateLimit(lggr logger.Logger, cfg RateLimitConfig) gin.HandlerFunc {
	// If rate limiting is not enabled, return a no-op middleware
	if !cfg.Enabled {
		lggr.Warn("Rate limiting is not enabled")
		return func(c *gin.Context) {
			c.Next()
		}
	}

	// Apply defaults if Period or Limit is 0
	period := cfg.Period
	if period == 0 {
		period = DefaultRateLimit.Period
	}

	limit := cfg.Limit
	if limit == 0 {
		limit = DefaultRateLimit.Limit
	}

	rate := limiter.Rate{
		Period: period,
		Limit:  limit,
	}

	store := memory.NewStore()
	instance := limiter.New(store, rate)

	lggr.Infow("Rate limiting enabled", "period", period, "limit", limit)
	return mgin.NewMiddleware(instance)
}
