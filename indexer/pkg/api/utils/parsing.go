package utils

import (
	"fmt"
	"strconv"
	"strings"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func ParseSelectorTypes(sels string) ([]protocol.ChainSelector, error) {
	var selectorTypes []protocol.ChainSelector
	selectorTypesAsArrayOfStrings := strings.Split(sels, ",")
	for _, propertyTypeAsString := range selectorTypesAsArrayOfStrings {
		u, err := strconv.ParseUint(propertyTypeAsString, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chain selector: %s", propertyTypeAsString)
		}

		_, err = chain_selectors.GetSelectorFamily(u)
		if err != nil {
			return nil, fmt.Errorf("invalid chain selector: %d", u)
		}

		selectorTypes = append(selectorTypes, protocol.ChainSelector(u))
	}
	return selectorTypes, nil
}
