package api

import (
	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/api/health"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/api/middleware"
	v1 "github.com/smartcontractkit/chainlink-ccv/verifier/token/api/v1"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func NewHTTPAPI(
	lggr logger.Logger,
	storage protocol.VerifierResultsAPI,
	healthReporters []protocol.HealthReporter,
) *gin.Engine {
	router := gin.Default()
	router.Use(middleware.SecureRecovery(lggr))

	healthHandler := health.NewHealthStatus(healthReporters)
	router.GET("/health/live", healthHandler.HandleLiveness)
	router.GET("/health/ready", healthHandler.HandleReadiness)
	router.GET("/health", healthHandler.HandleReadiness)

	// TODO This API will be publicly accessible, so we need a rate limiter to guard it CCIP-8878
	// Consider adding middleware similar to the one in Indexer endpoints
	v1Group := router.Group("/v1")
	verifierResultsHandler := v1.NewVerifierResultsHandler(lggr, storage)
	v1Group.GET("/verification/results", verifierResultsHandler.Handle)

	return router
}
