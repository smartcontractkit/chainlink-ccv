package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
)

var DefaultRateLimit = limiter.Rate{
	Period: 1 * time.Second,
	Limit:  1,
}

func RateLimit(lggr logger.Logger, cfg *config.Config) gin.HandlerFunc {
	store := memory.NewStore()
	instance := limiter.New(store, DefaultRateLimit)

	// If rate limiting is enabled, return the rate limiting middleware
	if cfg.API.RateLimit.Enabled {
		lggr.Info("Rate limiting enabled")
		return mgin.NewMiddleware(instance)
	}

	// If rate limiting is not enabled, return a no-op middleware
	lggr.Warn("Rate limiting is not enabled")
	return func(c *gin.Context) {
		c.Next()
	}
}
