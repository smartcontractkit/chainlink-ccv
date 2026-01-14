package v1

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	v1 "github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/v1"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// VerifierResultsHandler handles HTTP requests for verifier results.
type VerifierResultsHandler struct {
	lggr                  logger.Logger
	storage               protocol.VerifierResultsAPI
	maxMessageIDsPerBatch int
}

func NewVerifierResultsHandler(
	lggr logger.Logger,
	storage protocol.VerifierResultsAPI,
) *VerifierResultsHandler {
	return &VerifierResultsHandler{
		lggr:                  lggr,
		storage:               storage,
		maxMessageIDsPerBatch: 20,
	}
}

// Handle processes GET requests with message_ids as query parameters
// Expected query parameter format: ?message_ids=0x123abc,0x456def,...
func (h *VerifierResultsHandler) Handle(c *gin.Context) {
	// Get message_ids from query parameters
	messageIDsParam := c.Query("message_ids")
	if messageIDsParam == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "message_ids query parameter is required"})
		return
	}

	// Split by comma to get individual message IDs
	messageIDStrings := strings.Split(messageIDsParam, ",")
	if len(messageIDStrings) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "message_ids cannot be empty"})
		return
	}

	if len(messageIDStrings) > h.maxMessageIDsPerBatch {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf(
				"too many message_ids: %d, maximum allowed: %d",
				len(messageIDStrings),
				h.maxMessageIDsPerBatch),
		})
		return
	}

	messageIDs := make([]protocol.Bytes32, 0, len(messageIDStrings))
	for _, msgIDStr := range messageIDStrings {
		msgID, err := protocol.NewBytes32FromString(strings.TrimSpace(msgIDStr))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("invalid message_id format: %s - %v", msgIDStr, err),
			})
			return
		}
		messageIDs = append(messageIDs, msgID)
	}

	results, err := h.storage.GetVerifications(c.Request.Context(), messageIDs)
	if err != nil {
		h.lggr.Errorf("Failed to retrieve batch CCV data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve batch data"})
		return
	}

	// Process each message ID in order to maintain index correspondence
	apiResults := make([]v1.VerifierResult, 0, len(messageIDs))
	errors := make([]string, 0)
	for _, messageID := range messageIDs {
		result, ok := results[messageID]
		if !ok {
			errors = append(errors, "message not found: "+messageID.String())
			continue
		}

		apiResult, err := v1.NewVerifierResult(result)
		if err != nil {
			errors = append(errors, "failed to convert result for "+messageID.String()+": "+err.Error())
			continue
		}
		apiResults = append(apiResults, apiResult)
	}

	response := v1.NewVerifierResultsResponse(
		apiResults,
		errors,
	)

	c.JSON(http.StatusOK, response)
}
