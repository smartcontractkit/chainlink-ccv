package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/utils"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sourceChainSelectors, ok := utils.ParseSelectorTypes(c, "sourceChainSelectors")
	if !ok {
		return
	}
	destChainSelectors, ok := utils.ParseSelectorTypes(c, "destChainSelectors")
	if !ok {
		return
	}
	req.SourceChainSelectors = sourceChainSelectors
	req.DestChainSelectors = destChainSelectors

	messages, err := h.storage.QueryMessages(c.Request.Context(), req.Start, req.End, req.SourceChainSelectors, req.DestChainSelectors, req.Limit, req.Offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Convert the messages to a map of messageID to message
	messageMap := make(map[string]common.MessageWithMetadata)
	for _, msg := range messages {
		messageMap[msg.Message.MustMessageID().String()] = msg
	}

	h.lggr.Debugw("/v1/messages", "number of messages returned", len(messageMap))
	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"messages": messageMap,
	})
}

func (h *MessagesHandler) defaultRequestParams() MessagesRequest {
	return MessagesRequest{
		Start:                0,
		End:                  time.Now().UnixMilli(),
		SourceChainSelectors: []protocol.ChainSelector{},
		DestChainSelectors:   []protocol.ChainSelector{},
		Limit:                100,
		Offset:               0,
	}
}
