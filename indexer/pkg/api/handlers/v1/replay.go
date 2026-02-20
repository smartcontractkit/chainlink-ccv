package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type ReplayInput struct {
	// SourceChainSelectors []protocol.ChainSelector `doc:"Source chain selectors to filter results by. If empty, results from all source chains will be returned."                                             query:"sourceChainSelectors"`
	// DestChainSelectors   []protocol.ChainSelector `doc:"Destination chain selectors to filter results by. If empty, results from all destination chains will be returned."                                   query:"destChainSelectors"`
	// Start                string                   `doc:"Start time used to filter results. If not provided, results start from the beginning. Accepted formats: RFC3339, unix epoch time (in milliseconds)." form:"start"                 query:"start"`
	// End                  string                   `doc:"End time used to filter results. If not provided, the current server time is used. Accepted formats: RFC3339, unix epoch time (in milliseconds)."    form:"end"                   query:"end"`
	// Limit                uint64                   `doc:"Maximum number of results to return. If not provided, defaults to 100."                                                                              form:"limit"                 query:"limit"`
	// Offset               uint64                   `doc:"Number of results to skip before starting to return results. If not provided, defaults to 0."                                                        form:"offset"                query:"offset"`
}

type ReplayResponse struct {
	Success bool `json:"success" doc:"Indicates whether the request was successful."`
	// VerifierResults map[string][]common.VerifierResultWithMetadata `json:"verifierResults" doc:"A map of message IDs to their corresponding verifier results. Each key is a message ID, and the value is a list of verifier results associated with that message."`
}

type ReplayHandler struct {
	// storage    common.IndexerStorage
	lggr       logger.Logger
	monitoring common.IndexerMonitoring
}

func NewReplayHandler(lggr logger.Logger, monitoring common.IndexerMonitoring) *ReplayHandler {
	return &ReplayHandler{
		lggr:       lggr,
		monitoring: monitoring,
	}
}

func (h *ReplayHandler) Handle(c *gin.Context) {
	/*
		req := ReplayInput{}

		if err := c.ShouldBindQuery(&req); err != nil {
			c.JSON(http.StatusBadRequest, makeErrorResponse(http.StatusBadRequest, err.Error()))
			return
		}
		verifierResponse, err := h.storage.QueryCCVData(c.Request.Context(), startTime, endTime, req.SourceChainSelectors, req.DestChainSelectors, req.Limit, req.Offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, makeErrorResponse(http.StatusInternalServerError, err.Error()))
			return
		}

		h.lggr.Debugw("/v1/verifierresults", "number of messages returned", len(verifierResponse))
		c.JSON(http.StatusOK, VerifierResultsResponse{
			Success:         true,
			VerifierResults: verifierResponse,
		})
	*/
	h.lggr.Debugw("/v1/replay")
	c.JSON(http.StatusOK, VerifierResultsResponse{
		Success: true,
		// VerifierResults: verifierResponse,
	})
}
