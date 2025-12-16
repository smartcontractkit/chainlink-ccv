package v1

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type MessageIDInput struct {
	MessageID string `json:"messageId"`
}

type MessageIDResponse struct {
	Success   bool                                `json:"success"`
	Results   []common.VerifierResultWithMetadata `json:"results"`
	MessageID protocol.Bytes32                    `json:"messageID"`
}

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
		c.JSON(http.StatusBadRequest, makeErrorResponse("Invalid MessageID"))
		return
	}

	// Get all verifications for the messageID
	verifications, err := h.storage.GetCCVData(c.Request.Context(), messageIDBytes32)
	if err != nil {
		h.lggr.Errorf("Error retrieving CCV data for MessageID %s: %v", messageID, err)
	}

	switch {
	case errors.Is(err, storage.ErrCCVDataNotFound):
		c.JSON(http.StatusNotFound, makeErrorResponse("MessageID not found"))
		return
	case err == nil:
	default:
		c.JSON(http.StatusInternalServerError, makeErrorResponse("Internal Server Error"))
		return
	}

	c.JSON(http.StatusOK, MessageIDResponse{
		Success:   true,
		Results:   verifications,
		MessageID: messageIDBytes32,
	})
}
