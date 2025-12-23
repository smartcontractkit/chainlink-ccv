package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/middleware"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func NewV1API(lggr logger.Logger, cfg *config.Config, storage common.IndexerStorage, monitoring common.IndexerMonitoring) *gin.Engine {
	router := gin.Default()
	err := router.SetTrustedProxies(cfg.API.TrustedProxies)
	if err != nil {
		lggr.Fatalf("Unable to set Trusted Proxies", "error", err, "trustedProxies", cfg.API.TrustedProxies)
	}

	// Add the active requests middleware to all routes
	router.Use(middleware.ActiveRequestsMiddleware(monitoring, lggr))
	router.Use(middleware.RateLimit(lggr, cfg))

	v1Group := router.Group("/v1")

	// View all known verifications over a time range
	verifierResponseHandler := v1.NewVerifierResultHandler(storage, lggr, monitoring)
	v1Group.GET("/verifierresult", verifierResponseHandler.Handle)

	// Get all messages over a time range
	messagesHandler := v1.NewMessagesHandler(storage, lggr, monitoring)
	v1Group.GET("/messages", messagesHandler.Handle)

	// Get all verifications for a specific messageID
	messageIDHandler := v1.NewMessageIDHandler(storage, lggr, monitoring)
	v1Group.GET("/messageid/:messageID", messageIDHandler.Handle)

	return router
}

func Serve(router *gin.Engine, port int) {
	err := router.Run(fmt.Sprintf(":%d", port))
	if err != nil {
		panic(err)
	}
}
