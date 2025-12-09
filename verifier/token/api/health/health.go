package health

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
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
	c.JSON(http.StatusOK, gin.H{
		"status": "alive",
	})
}

// HandleReadiness checks if the service is ready to accept traffic.
// This checks that all health reporters are properly started and running.
// Note: 0 health reporters is a valid idle state and the service is considered ready.
// Kubernetes will remove the pod from service endpoints if this fails.
func (h *Status) HandleReadiness(c *gin.Context) {
	reporterStatuses := make([]ServicesHealth, 0, len(h.healthReporters))
	hasErrors := false

	// 0 health reporters is a valid idle state - service can still accept API requests
	for _, reporter := range h.healthReporters {
		hasErrors = hasErrors || (reporter.Ready() != nil)
		reporterStatuses = append(
			reporterStatuses,
			NewServiceHealth(reporter),
		)
	}

	if hasErrors {
		c.JSON(
			http.StatusServiceUnavailable,
			NewResponse(NotReady, reporterStatuses),
		)
		return
	}

	c.JSON(
		http.StatusOK,
		NewResponse(Ready, reporterStatuses),
	)
}
