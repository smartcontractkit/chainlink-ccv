package utils

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func ParseSelectorTypes(sels string) ([]protocol.ChainSelector, error) {
	selectorTypesAsArrayOfStrings := strings.Split(sels, ",")
	selectorTypes := make([]protocol.ChainSelector, 0, len(selectorTypesAsArrayOfStrings))
	for _, propertyTypeAsString := range selectorTypesAsArrayOfStrings {
		u, err := strconv.ParseUint(propertyTypeAsString, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chain selector: %s", err.Error())
		}

		selectorTypes = append(selectorTypes, protocol.ChainSelector(u))
	}
	return selectorTypes, nil
}
