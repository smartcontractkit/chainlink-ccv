package utils

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func ParseSelectorTypes(c *gin.Context, paramName string) ([]protocol.ChainSelector, bool) {
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
