package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"

	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
)

var DefaultRateLimit = limiter.Rate{
	Period: 1 * time.Second,
	Limit:  1,
}

func RateLimit() gin.HandlerFunc {
	store := memory.NewStore()
	instance := limiter.New(store, DefaultRateLimit)

	return mgin.NewMiddleware(instance)
}
