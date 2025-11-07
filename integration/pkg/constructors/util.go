package constructors

import (
	"fmt"
	"strconv"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func mapAddresses(addresses map[string]string) (map[protocol.ChainSelector]protocol.UnknownAddress, error) {
	mapped := make(map[protocol.ChainSelector]protocol.UnknownAddress)
	for strSel, addrStr := range addresses {
		selector, err := strconv.ParseUint(strSel, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse selector '%s': %w", strSel, err)
		}

		addr, err := protocol.NewUnknownAddressFromHex(addrStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse address '%s': %w", strSel, err)
		}
		mapped[protocol.ChainSelector(selector)] = addr
	}
	return mapped, nil
}
