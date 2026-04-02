package accessors

import (
	"fmt"
	"strconv"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// TODO: Infos belongs with the registry.

// Infos is a map of more than one Info.
type Infos[T any] map[string]T

// GetBlockchainByChainSelector returns the blockchain info for a given chain selector.
func (bh Infos[T]) GetBlockchainByChainSelector(chainSelector protocol.ChainSelector) (T, error) {
	selector := fmt.Sprintf("%d", uint64(chainSelector))
	if info, exists := bh[selector]; exists {
		return info, nil
	}
	var empty T
	return empty, fmt.Errorf("selector %d not found", uint64(chainSelector))
}

// GetAllInfos returns all blockchain infos mapped by their chain selectors.
func (bh Infos[T]) GetAllInfos() map[protocol.ChainSelector]T {
	i := make(map[protocol.ChainSelector]T)
	for sel := range bh {
		selector, err := strconv.ParseUint(sel, 10, 64)
		if err != nil {
			continue
		}
		i[protocol.ChainSelector(selector)] = bh[sel]
	}
	return i
}

// GetAllChainSelectors returns all available chain selectors.
func (bh Infos[T]) GetAllChainSelectors() []protocol.ChainSelector {
	infos := bh.GetAllInfos()
	selectors := make([]protocol.ChainSelector, 0, len(infos))
	for sel := range infos {
		selectors = append(selectors, sel)
	}
	return selectors
}
