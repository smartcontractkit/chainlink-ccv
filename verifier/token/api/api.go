package api

import (
	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/middleware"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/api/health"
	apimiddleware "github.com/smartcontractkit/chainlink-ccv/verifier/token/api/middleware"
	v1 "github.com/smartcontractkit/chainlink-ccv/verifier/token/api/v1"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func NewHTTPAPI(
	lggr logger.Logger,
	storage protocol.VerifierResultsAPI,
	healthReporters []protocol.HealthReporter,
	monitoring verifier.Monitoring,
) *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(middleware.SecureRecovery(lggr))

	healthHandler := health.NewHealthStatus(healthReporters)
	router.GET("/health/live", healthHandler.HandleLiveness)
	router.GET("/health/ready", healthHandler.HandleReadiness)
	router.GET("/health", healthHandler.HandleReadiness)

	v1Group := router.Group("/v1")
	// Apply metrics middleware only to v1 endpoints
	v1Group.Use(middleware.ActiveRequestsMiddleware(
		monitoring.Metrics(),
		apimiddleware.VerificationsPathNormalizer,
		lggr,
	))
	// Apply rate limiting with defaults (10 req/s per IP)
	v1Group.Use(middleware.RateLimit(lggr, middleware.RateLimitConfig{
		Enabled: true,
		Period:  0, // Will use DefaultRateLimit.Period (1 second)
		Limit:   0, // Will use DefaultRateLimit.Limit (10 requests)
	}))
	verifierResultsHandler := v1.NewVerifierResultsHandler(lggr, storage)
	v1Group.GET("/verifications", verifierResultsHandler.Handle)

	return router
}
