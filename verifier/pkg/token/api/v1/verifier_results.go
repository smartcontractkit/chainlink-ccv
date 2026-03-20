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

// Handle processes GET requests with messageID as query parameters
// Expected query parameter format: ?messageID=0x123abc&messageID=0x456def&...
func (h *VerifierResultsHandler) Handle(c *gin.Context) {
	// Get messageID from query parameters (supports multiple values)
	messageIDStrings := c.QueryArray("messageID")
	if len(messageIDStrings) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "messageID query parameter is required"})
		return
	}

	if len(messageIDStrings) > h.maxMessageIDsPerBatch {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf(
				"too many messageIDs: %d, maximum allowed: %d",
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
				"error": "invalid messageID format",
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

	// If no results were found at all, return 404 Not Found
	// If at least one result was found (partial success), return 200 OK
	if len(apiResults) == 0 && len(errors) > 0 {
		c.JSON(http.StatusNotFound, response)
	} else {
		c.JSON(http.StatusOK, response)
	}
}
