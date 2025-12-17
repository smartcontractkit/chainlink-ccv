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

type MessagesInput struct {
	SourceChainSelectors []protocol.ChainSelector `query:"sourceChainSelectors"` // Excluded from form due to gin parsing
	DestChainSelectors   []protocol.ChainSelector `query:"destChainSelectors"`   // Excluded from form due to gin parsing
	Start                int64                    `form:"start"                 query:"start"`
	End                  int64                    `form:"end"                   query:"end"`
	Limit                uint64                   `form:"limit"                 query:"limit"`
	Offset               uint64                   `form:"offset"                query:"offset"`
}
type MessagesResponse struct {
	Success  bool                                  `json:"success"`
	Messages map[string]common.MessageWithMetadata `json:"messages"`
}
type MessagesHandler struct {
	storage    common.IndexerStorage
	lggr       logger.Logger
	monitoring common.IndexerMonitoring
}

func NewMessagesHandler(storage common.IndexerStorage, lggr logger.Logger, monitoring common.IndexerMonitoring) *MessagesHandler {
	return &MessagesHandler{
		storage:    storage,
		lggr:       lggr,
		monitoring: monitoring,
	}
}

func (h *MessagesHandler) Handle(c *gin.Context) {
	req := h.defaultRequestParams()

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

	messages, err := h.storage.QueryMessages(c.Request.Context(), req.Start, req.End, req.SourceChainSelectors, req.DestChainSelectors, req.Limit, req.Offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, makeErrorResponse(http.StatusInternalServerError, err.Error()))
		return
	}

	// Convert the messages to a map of messageID to message
	messageMap := make(map[string]common.MessageWithMetadata)
	for _, msg := range messages {
		messageMap[msg.Message.MustMessageID().String()] = msg
	}

	h.lggr.Debugw("/v1/messages", "number of messages returned", len(messageMap))
	c.JSON(http.StatusOK, MessagesResponse{
		Success:  true,
		Messages: messageMap,
	})
}

func (h *MessagesHandler) defaultRequestParams() MessagesInput {
	return MessagesInput{
		Start:                0,
		End:                  time.Now().UnixMilli(),
		SourceChainSelectors: []protocol.ChainSelector{},
		DestChainSelectors:   []protocol.ChainSelector{},
		Limit:                100,
		Offset:               0,
	}
}
