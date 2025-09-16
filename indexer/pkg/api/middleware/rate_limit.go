package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

var DefaultRateLimit = limiter.Rate{
	Period: 1 * time.Second,
	Limit:  1,
}

func RateLimit() gin.HandlerFunc {
	store := memory.NewStore()
	instance := limiter.New(store, DefaultRateLimit)

	return func(c *gin.Context) {
		ip := c.ClientIP()
		context, err := instance.Get(c, ip)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		if context.Reached {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}

		c.Next()
	}
}
