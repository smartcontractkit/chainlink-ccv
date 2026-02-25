package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type HealthHandler struct {
	storage    common.IndexerStorage
	lggr       logger.Logger
	monitoring common.IndexerMonitoring
}

func NewHealthHandler(storage common.IndexerStorage, lggr logger.Logger, monitoring common.IndexerMonitoring) *HealthHandler {
	return &HealthHandler{storage: storage, lggr: lggr, monitoring: monitoring}
}

// Handle responds to /health with HTTP 200.
func (h *HealthHandler) Handle(c *gin.Context) {
	c.Status(http.StatusOK)
}

// HandleReady responds to /ready with HTTP 200 after checking storage functionality.
func (h *HealthHandler) HandleReady(c *gin.Context) {
	// Try a lightweight storage call to verify storage functionality.
	// QueryMessages with a small limit is a simple read check.
	_, err := h.storage.QueryMessages(c.Request.Context(), 0, 0, []protocol.ChainSelector{}, []protocol.ChainSelector{}, 1, 0)
	if err != nil {
		h.lggr.Errorw("failed storage call QueryMessages for health check", "error", err)
		c.JSON(http.StatusInternalServerError, internalServerErrorResponse)
		return
	}

	c.Status(http.StatusOK)
}
