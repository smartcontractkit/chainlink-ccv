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
	reporterStatuses := make([]gin.H, 0, len(h.healthReporters))
	hasErrors := false

	// 0 health reporters is a valid idle state - service can still accept API requests
	for _, reporter := range h.healthReporters {
		if reporter == nil {
			hasErrors = true
			reporterStatuses = append(reporterStatuses, gin.H{
				"name":   "unknown",
				"status": "nil",
				"error":  "health reporter is nil",
			})
			continue
		}

		ready := reporter.Ready()
		status := "ready"
		var errorMsg any
		if ready != nil {
			status = "not_ready"
			errorMsg = ready.Error()
			hasErrors = true
		} else {
			errorMsg = nil
		}

		reporterStatuses = append(reporterStatuses, gin.H{
			"name":   reporter.Name(),
			"status": status,
			"error":  errorMsg,
		})
	}

	if hasErrors {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":   "not_ready",
			"services": reporterStatuses,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "ready",
		"services": reporterStatuses,
	})
}
