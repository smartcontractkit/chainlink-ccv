package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/utils"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type CCVDataV1Handler struct {
	storage    common.IndexerStorage
	lggr       logger.Logger
	monitoring common.IndexerMonitoring
}

func NewCCVDataV1Handler(storage common.IndexerStorage, lggr logger.Logger, monitoring common.IndexerMonitoring) *CCVDataV1Handler {
	return &CCVDataV1Handler{
		storage:    storage,
		lggr:       lggr,
		monitoring: monitoring,
	}
}

func (h *CCVDataV1Handler) Handle(c *gin.Context) {
	req := storageaccess.VerifierResultsRequest{
		Start:                0,
		End:                  time.Now().Unix(),
		SourceChainSelectors: []protocol.ChainSelector{},
		DestChainSelectors:   []protocol.ChainSelector{},
		Limit:                100,
		Offset:               0,
	}

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

	ccvData, err := h.storage.QueryCCVData(c.Request.Context(), req.Start, req.End, req.SourceChainSelectors, req.DestChainSelectors, req.Limit, req.Offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.lggr.Debugw("/v1/ccvdata", "number of messages returned", len(ccvData))
	c.JSON(http.StatusOK, gin.H{"success": true, "ccvData": ccvData})
}
