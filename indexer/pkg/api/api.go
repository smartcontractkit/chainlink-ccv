package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/middleware"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	sharedmiddleware "github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/middleware"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func NewV1API(lggr logger.Logger, cfg *config.Config, storage common.IndexerStorage, monitoring common.IndexerMonitoring) *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger())
	err := router.SetTrustedProxies(cfg.API.TrustedProxies)
	if err != nil {
		lggr.Fatalf("Unable to set Trusted Proxies", "error", err, "trustedProxies", cfg.API.TrustedProxies)
	}

	// Add the active requests middleware to all routes
	router.Use(sharedmiddleware.ActiveRequestsMiddleware(
		monitoring.Metrics(),
		middleware.RemoveMessageIDFromPath,
		lggr,
	))
	router.Use(middleware.RateLimit(lggr, cfg))
	router.Use(sharedmiddleware.SecureRecovery(lggr))

	v1Group := router.Group("/v1")

	// View all known verifications over a time range
	verifierResponseHandler := v1.NewVerifierResultsHandler(storage, lggr, monitoring, v1.MaxQueryLimit)
	v1Group.GET("/verifierresults", verifierResponseHandler.Handle)

	// Get all verifications for a specific messageID
	messageIDHandler := v1.NewVerifierResultsByMessageIDHandler(storage, lggr, monitoring)
	v1Group.GET("/verifierresults/:messageID", messageIDHandler.Handle)

	// Get all messages over a time range
	messagesHandler := v1.NewMessagesHandler(storage, lggr, monitoring, v1.MaxQueryLimit)
	v1Group.GET("/messages", messagesHandler.Handle)

	// App readiness and health endpoints
	healthHandler := v1.NewHealthHandler(storage, lggr, monitoring)
	router.GET("/health", healthHandler.Handle)
	router.GET("/ready", healthHandler.HandleReady)

	return router
}

func Serve(router *gin.Engine, port int) {
	err := router.Run(fmt.Sprintf(":%d", port))
	if err != nil {
		panic(err)
	}
}
