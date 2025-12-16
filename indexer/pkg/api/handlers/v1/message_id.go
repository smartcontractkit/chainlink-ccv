package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type MessageIDHandler struct {
	storage    common.IndexerStorage
	lggr       logger.Logger
	monitoring common.IndexerMonitoring
}

func NewMessageIDHandler(storage common.IndexerStorage, lggr logger.Logger, monitoring common.IndexerMonitoring) *MessageIDHandler {
	return &MessageIDHandler{
		storage:    storage,
		lggr:       lggr,
		monitoring: monitoring,
	}
}

func (h *MessageIDHandler) Handle(c *gin.Context) {
	messageID := c.Param("messageID")
	messageIDBytes32, err := protocol.NewBytes32FromString(messageID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid MessageID"})
		return
	}

	// Get all verifications for the messageID
	verifications, err := h.storage.GetCCVData(c.Request.Context(), messageIDBytes32)

	switch err {
	case storage.ErrCCVDataNotFound:
		c.JSON(http.StatusNotFound, gin.H{"error": "MessageID not found"})
		return
	case nil:
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"results":   verifications,
		"messageID": messageID,
	})
}
