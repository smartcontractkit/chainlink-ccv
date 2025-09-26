package v1

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
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

	startDuration := time.Now()

	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sourceChainSelectors, ok := h.parseSelectorTypes(c, "sourceChainSelectors")
	if !ok {
		return
	}
	destChainSelectors, ok := h.parseSelectorTypes(c, "destChainSelectors")
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

	h.lggr.Debugw("ccvData ", "ccvData", ccvData)
	c.JSON(http.StatusOK, gin.H{"success": true, "ccvData": ccvData})
	h.monitoring.Metrics().RecordVerificationRecordRequestDuration(c.Request.Context(), time.Since(startDuration))
}

func (h *CCVDataV1Handler) parseSelectorTypes(c *gin.Context, paramName string) ([]protocol.ChainSelector, bool) {
	var selectorTypes []protocol.ChainSelector
	var selectorTypesAsString string
	var selectorTypesAsArrayOfStrings []string
	selectorTypesAsString, success := c.GetQuery(paramName)
	selectorTypesAsArrayOfStrings = strings.Split(selectorTypesAsString, ",")
	if success {
		for _, propertyTypeAsString := range selectorTypesAsArrayOfStrings {
			u, err := strconv.ParseUint(propertyTypeAsString, 10, 64)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Request", "status": http.StatusBadRequest})
				return nil, false
			}
			selectorTypes = append(selectorTypes, protocol.ChainSelector(u)) // #nosec G115
		}
	}
	return selectorTypes, true
}
