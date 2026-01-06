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

type VerifierResultsByMessageIDInput struct {
	MessageID string `json:"messageId" path:"messageID"`
}

type VerifierResultsByMessageIDResponse struct {
	Success   bool                                `json:"success"   doc:"Indicates whether the request was successful."`
	Results   []common.VerifierResultWithMetadata `json:"results"   doc:"A list of verifier results associated with the specified message ID."`
	MessageID protocol.Bytes32                    `json:"messageID" doc:"The message ID for which the verifier results are being returned."`
}

type VerifierResultsByMessageIDHandler struct {
	storage    common.IndexerStorage
	lggr       logger.Logger
	monitoring common.IndexerMonitoring
}

func NewVerifierResultsByMessageIDHandler(storage common.IndexerStorage, lggr logger.Logger, monitoring common.IndexerMonitoring) *VerifierResultsByMessageIDHandler {
	return &VerifierResultsByMessageIDHandler{
		storage:    storage,
		lggr:       lggr,
		monitoring: monitoring,
	}
}

func (h *VerifierResultsByMessageIDHandler) Handle(c *gin.Context) {
	messageID := c.Param("messageID")
	messageIDBytes32, err := protocol.NewBytes32FromString(messageID)
	if err != nil {
		c.JSON(http.StatusBadRequest, makeErrorResponse(http.StatusBadRequest, "Invalid MessageID"))
		return
	}

	// Get all verifications for the messageID
	verifications, err := h.storage.GetCCVData(c.Request.Context(), messageIDBytes32)
	if err != nil {
		h.lggr.Errorf("Error retrieving CCV data for MessageID %s: %v", messageID, err)
	}

	switch {
	case errors.Is(err, storage.ErrCCVDataNotFound):
		c.JSON(http.StatusNotFound, makeErrorResponse(http.StatusNotFound, "MessageID not found"))
		return
	case err == nil:
	default:
		c.JSON(http.StatusInternalServerError, makeErrorResponse(http.StatusInternalServerError, "Internal Server Error"))
		return
	}

	c.JSON(http.StatusOK, VerifierResultsByMessageIDResponse{
		Success:   true,
		Results:   verifications,
		MessageID: messageIDBytes32,
	})
}
