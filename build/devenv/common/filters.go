package common

import (
	chainsel "github.com/smartcontractkit/chain-selectors"
)

// FilterLombardSupportedSelectors returns only the selectors whose chain family
// has a registered adapter in the global Lombard registry.
func FilterLombardSupportedSelectors(remoteSelectors []uint64) []uint64 {
	supported := make([]uint64, 0)
	for _, rs := range remoteSelectors {
		family, err := chainsel.GetSelectorFamily(rs)
		if err != nil {
			continue
		}
		if _, ok := GlobalLombardRegistry.GetLombardChain(family); ok {
			supported = append(supported, rs)
		}
	}
	return supported
}

// FilterCCTPSupportedSelectors returns only the selectors whose chain family
// has a registered adapter in the global CCTP registry.
func FilterCCTPSupportedSelectors(remoteSelectors []uint64) []uint64 {
	supported := make([]uint64, 0)
	for _, rs := range remoteSelectors {
		family, err := chainsel.GetSelectorFamily(rs)
		if err != nil {
			continue
		}
		if HasCCTPChainFamily(GlobalCCTPRegistry, family) {
			supported = append(supported, rs)
		}
	}
	return supported
}
