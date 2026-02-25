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
	SourceChainSelectors []protocol.ChainSelector `doc:"Source chain selectors to filter results by. If empty, results from all source chains will be returned."                                                                                query:"sourceChainSelectors"`
	DestChainSelectors   []protocol.ChainSelector `doc:"Destination chain selectors to filter results by. If empty, results from all destination chains will be returned."                                                                      query:"destChainSelectors"`
	Start                string                   `doc:"Start time used to filter results. If not provided, results start from the beginning. Accepted formats: RFC3339, unix epoch time (in milliseconds)."                                    form:"start"                 query:"start"`
	End                  string                   `doc:"End time used to filter results. If not provided, the current server time is used. Accepted formats: RFC3339, unix epoch time (in milliseconds)."                                       form:"end"                   query:"end"`
	Limit                uint64                   `doc:"Maximum number of results to return. If not provided, defaults to 100. Maximum allowed is 1000; Requests with a limit greater than 1000 will be rejected with a 400 bad request error." form:"limit"                 query:"limit"`
	Offset               uint64                   `doc:"Number of results to skip before starting to return results. If not provided, defaults to 0."                                                                                           form:"offset"                query:"offset"`
}

type VerifierResultsResponse struct {
	Success         bool                                           `json:"success"         doc:"Indicates whether the request was successful."`
	VerifierResults map[string][]common.VerifierResultWithMetadata `json:"verifierResults" doc:"A map of message IDs to their corresponding verifier results. Each key is a message ID, and the value is a list of verifier results associated with that message."`
}

type VerifierResultsHandler struct {
	storage       common.IndexerStorage
	lggr          logger.Logger
	monitoring    common.IndexerMonitoring
	maxQueryLimit uint64
}

func NewVerifierResultsHandler(storage common.IndexerStorage, lggr logger.Logger, monitoring common.IndexerMonitoring, maxQueryLimit uint64) *VerifierResultsHandler {
	return &VerifierResultsHandler{
		storage:       storage,
		lggr:          lggr,
		monitoring:    monitoring,
		maxQueryLimit: maxQueryLimit,
	}
}

func (h *VerifierResultsHandler) Handle(c *gin.Context) {
	req := VerifierResultsInput{
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

	verifierResponse, err := h.storage.QueryCCVData(c.Request.Context(), startTime, endTime, req.SourceChainSelectors, req.DestChainSelectors, req.Limit, req.Offset)
	if err != nil {
		h.lggr.Errorw("failed storage call QueryCCVData", "request", req, "error", err)
		c.JSON(http.StatusInternalServerError, internalServerErrorResponse)
		return
	}

	h.lggr.Debugw("/v1/verifierresults", "number of messages returned", len(verifierResponse))
	c.JSON(http.StatusOK, VerifierResultsResponse{
		Success:         true,
		VerifierResults: verifierResponse,
	})
}
