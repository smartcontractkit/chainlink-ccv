package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/middleware"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
)

func NewV1API(lggr logger.Logger, cfg *config.Config, storage common.IndexerStorage, monitoring common.IndexerMonitoring) *gin.Engine {
	router := gin.Default()

	// Add the active requests middleware to all routes
	router.Use(middleware.ActiveRequestsMiddleware(monitoring, lggr))
	router.Use(middleware.RateLimit(lggr, cfg))

	v1Group := router.Group("/v1")

	// View all known verifications over a time range
	ccvDataV1Handler := v1.NewCCVDataHandler(storage, lggr, monitoring)
	v1Group.GET("/verifierresult", ccvDataV1Handler.Handle)

	// Get all messages over a time range
	messagesV1Handler := v1.NewMessagesV1Handler(storage, lggr, monitoring)
	v1Group.GET("/messages", messagesV1Handler.Handle)

	// Get all verifications for a specific messageID
	messageIDV1Handler := v1.NewMessageIDV1Handler(storage, lggr, monitoring)
	v1Group.GET("/messageid/:messageID", messageIDV1Handler.Handle)

	return router
}

func Serve(router *gin.Engine, port int) {
	err := router.Run(fmt.Sprintf(":%d", port))
	if err != nil {
		panic(err)
	}
}
