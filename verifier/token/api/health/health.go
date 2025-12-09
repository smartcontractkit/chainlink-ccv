package health

import (
	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/health"
)

type Status struct {
	healthReporters []protocol.HealthReporter
}

func NewHealthStatus(healthReporters []protocol.HealthReporter) *Status {
	return &Status{
		healthReporters: healthReporters,
	}
}

// HandleLiveness checks if the service is alive and responding.
// This is a simple check - if the HTTP server can respond, the process is alive.
// Kubernetes will restart the pod if this fails.
func (h *Status) HandleLiveness(c *gin.Context) {
	response := health.NewLivenessResponse()
	c.JSON(
		response.StatusCode(), response,
	)
}

// HandleReadiness checks if the service is ready to accept traffic.
// This checks that all health reporters are properly started and running.
// Note: 0 health reporters is a valid idle state and the service is considered ready.
// Kubernetes will remove the pod from service endpoints if this fails.
func (h *Status) HandleReadiness(c *gin.Context) {
	reporterStatuses := make([]health.ServicesHealth, 0, len(h.healthReporters))

	// 0 health reporters is a valid idle state - service can still accept API requests
	for _, reporter := range h.healthReporters {
		reporterStatuses = append(
			reporterStatuses,
			health.NewServiceHealth(reporter),
		)
	}

	response := health.NewReadinessResponse(reporterStatuses)
	c.JSON(
		response.StatusCode(),
		response,
	)
}
