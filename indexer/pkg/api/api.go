package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
)

func NewV1API(lggr logger.Logger, storage common.IndexerStorage) *gin.Engine {
	router := gin.Default()
	v1Group := router.Group("/v1")

	v1Group.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	ccvDataV1Handler := v1.NewCCVDataV1Handler(storage, lggr)
	v1Group.GET("/ccvdata", ccvDataV1Handler.Handle)

	return router
}

func Serve(router *gin.Engine, port int) error {
	return router.Run(fmt.Sprintf(":%d", port))
}
