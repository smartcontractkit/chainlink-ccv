package health

import (
	"github.com/gin-gonic/gin"
)

// Status is a gin adapter over Manager, for services that mount their health routes
// on an existing gin router (e.g. token-verifier, indexer) rather than owning their
// own HTTP server.
type Status struct {
	manager *Manager
}

func NewHealthStatus(manager *Manager) *Status {
	return &Status{
		manager: manager,
	}
}

// HandleLiveness checks if the service is alive and responding.
// This is a simple check - if the HTTP server can respond, the process is alive.
// Kubernetes will restart the pod if this fails.
func (h *Status) HandleLiveness(c *gin.Context) {
	response := h.manager.CheckLiveness(c.Request.Context())
	c.JSON(
		response.StatusCode(), response,
	)
}

// HandleReadiness checks if the service is ready to accept traffic.
// This checks that all health reporters are properly started and running.
// Note: 0 health reporters is a valid idle state and the service is considered ready.
// Kubernetes will remove the pod from service endpoints if this fails.
func (h *Status) HandleReadiness(c *gin.Context) {
	response := h.manager.CheckReadiness(c.Request.Context())
	c.JSON(
		response.StatusCode(),
		response,
	)
}
