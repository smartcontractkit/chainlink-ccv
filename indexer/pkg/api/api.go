package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/middleware"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	v1Handlers "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
)

func NewV1API(lggr logger.Logger, storage common.IndexerStorage) *gin.Engine {
	router := gin.Default()
	router.Use(middleware.RateLimit())

	v1 := router.Group("/v1")

	v1.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	ccvDataV1Handler := v1Handlers.NewCCVDataV1Handler(storage, lggr)
	v1.GET("/ccvdata", ccvDataV1Handler.Handle)

	return router
}

func Serve(router *gin.Engine, port int) {
	router.Run(fmt.Sprintf(":%d", port))
}
