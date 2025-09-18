package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	handlerv1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
)

func NewV1API(lggr logger.Logger, storage common.IndexerStorage) *gin.Engine {
	router := gin.Default()
	v1 := router.Group("/v1")

	v1.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	ccvDataV1Handler := handlerv1.NewCCVDataV1Handler(storage, lggr)
	v1.GET("/ccvdata", ccvDataV1Handler.Handle)

	return router
}

func Serve(router *gin.Engine, port int) {
	err := router.Run(fmt.Sprintf(":%d", port))
	if err != nil {
		panic(err)
	}
}
