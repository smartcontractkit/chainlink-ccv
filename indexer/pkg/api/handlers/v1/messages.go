package v1

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/utils"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type MessagesInput = VerifierResultsInput

type MessagesResponse struct {
	Success  bool                                  `json:"success"  doc:"Indicates whether the request was successful."`
	Messages map[string]common.MessageWithMetadata `json:"messages" doc:"A map of message IDs to their corresponding messages. Each key is a message ID, and the value is the message along with its metadata."`
}
type MessagesHandler struct {
	storage       common.IndexerStorage
	lggr          logger.Logger
	monitoring    common.IndexerMonitoring
	maxQueryLimit uint64
}

func NewMessagesHandler(storage common.IndexerStorage, lggr logger.Logger, monitoring common.IndexerMonitoring, maxQueryLimit uint64) *MessagesHandler {
	return &MessagesHandler{
		storage:       storage,
		lggr:          lggr,
		monitoring:    monitoring,
		maxQueryLimit: maxQueryLimit,
	}
}

func (h *MessagesHandler) Handle(c *gin.Context) {
	req := MessagesInput{
		End:                  time.Now().Format(time.RFC3339),
		SourceChainSelectors: []protocol.ChainSelector{},
		DestChainSelectors:   []protocol.ChainSelector{},
		Limit:                100,
		Offset:               0,
	}

	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, makeErrorResponse(http.StatusBadRequest, err.Error()))
		return
	}

	sourceChainSelectors, err := utils.ParseSelectorTypes(c.DefaultQuery("sourceChainSelectors", ""))
	if err != nil {
		c.JSON(http.StatusBadRequest, makeErrorResponse(http.StatusBadRequest, fmt.Sprintf("bad sourceChainSelectors: %s", err.Error())))
		return
	}
	destChainSelectors, err := utils.ParseSelectorTypes(c.DefaultQuery("destChainSelectors", ""))
	if err != nil {
		c.JSON(http.StatusBadRequest, makeErrorResponse(http.StatusBadRequest, fmt.Sprintf("bad destChainSelectors: %s", err.Error())))
		return
	}
	req.SourceChainSelectors = sourceChainSelectors
	req.DestChainSelectors = destChainSelectors

	startTime, err := parseTime(req.Start)
	if err != nil {
		c.JSON(http.StatusBadRequest, makeErrorResponse(http.StatusBadRequest, fmt.Sprintf("bad start time: %s", err.Error())))
		return
	}
	endTime, err := parseTime(req.End)
	if err != nil {
		c.JSON(http.StatusBadRequest, makeErrorResponse(http.StatusBadRequest, fmt.Sprintf("bad end time: %s", err.Error())))
		return
	}

	if req.Limit > h.maxQueryLimit {
		h.lggr.Debugw("limit exceeded maximum", "requested", req.Limit, "max", h.maxQueryLimit)
		c.JSON(http.StatusBadRequest, makeErrorResponse(http.StatusBadRequest, fmt.Sprintf("limit exceeds maximum allowed (%d)", h.maxQueryLimit)))
		return
	}

	messages, err := h.storage.QueryMessages(c.Request.Context(), startTime, endTime, req.SourceChainSelectors, req.DestChainSelectors, req.Limit, req.Offset)
	if err != nil {
		h.lggr.Errorw("failed storage call QueryMessages", "request", req, "error", err)
		c.JSON(http.StatusInternalServerError, internalServerErrorResponse)
		return
	}

	// Convert the messages to a map of messageID to message
	messageMap := make(map[string]common.MessageWithMetadata)
	for _, msg := range messages {
		// Use the safe MessageID accessor to avoid panics and handle encoding errors.
		id, err := msg.Message.MessageID()
		if err != nil {
			// Log and skip messages that cannot be encoded into an ID
			h.lggr.Warnw("skipping message with invalid ID", "err", err)
			continue
		}
		if id.IsEmpty() {
			// Skip messages with an empty ID
			h.lggr.Warnw("skipping message with empty ID")
			continue
		}
		messageMap[id.String()] = msg
	}

	h.lggr.Debugw("/v1/messages", "number of messages returned", len(messageMap))
	c.JSON(http.StatusOK, MessagesResponse{
		Success:  true,
		Messages: messageMap,
	})
}
