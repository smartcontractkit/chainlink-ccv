package common

import (
	"github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/adapters"
)

var GlobalCCTPRegistry = adapters.NewCCTPChainRegistry()

func HasCCTPChainFamily(registry *adapters.CCTPChainRegistry, family string) bool {
	if _, ok := registry.GetCCTPChain(family, adapters.Canonical); ok {
		return true
	}
	if _, ok := registry.GetCCTPChain(family, adapters.NonCanonical); ok {
		return true
	}
	return false
}
