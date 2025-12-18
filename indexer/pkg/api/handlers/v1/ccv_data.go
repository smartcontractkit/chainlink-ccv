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

type VerifierResultsInput struct {
	SourceChainSelectors []protocol.ChainSelector `query:"sourceChainSelectors"` // Excluded from form due to gin parsing
	DestChainSelectors   []protocol.ChainSelector `query:"destChainSelectors"`   // Excluded from form due to gin parsing
	Start                int64                    `form:"start"                 query:"start"`
	End                  int64                    `form:"end"                   query:"end"`
	Limit                uint64                   `form:"limit"                 query:"limit"`
	Offset               uint64                   `form:"offset"                query:"offset"`
}

type VerifierResultsResponse struct {
	Success         bool                                           `json:"success"`
	VerifierResults map[string][]common.VerifierResultWithMetadata `json:"verifierResults"`
}

type VerifierResultsHandler struct {
	storage    common.IndexerStorage
	lggr       logger.Logger
	monitoring common.IndexerMonitoring
}

func NewVerifierResultsHandler(storage common.IndexerStorage, lggr logger.Logger, monitoring common.IndexerMonitoring) *VerifierResultsHandler {
	return &VerifierResultsHandler{
		storage:    storage,
		lggr:       lggr,
		monitoring: monitoring,
	}
}

func (h *VerifierResultsHandler) Handle(c *gin.Context) {
	req := VerifierResultsInput{
		Start:                0,
		End:                  time.Now().UnixMilli(),
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

	verifierResponse, err := h.storage.QueryCCVData(c.Request.Context(), req.Start, req.End, req.SourceChainSelectors, req.DestChainSelectors, req.Limit, req.Offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, makeErrorResponse(http.StatusInternalServerError, err.Error()))
		return
	}

	h.lggr.Debugw("/v1/verifierresult", "number of messages returned", len(verifierResponse))
	c.JSON(http.StatusOK, VerifierResultsResponse{
		Success:         true,
		VerifierResults: verifierResponse,
	})
}
