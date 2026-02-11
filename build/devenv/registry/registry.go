// Package registry provides a global chain family registry that can be used
// across packages without creating import cycles.
package registry

import (
	"sync"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	evmadapters "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	cantonadapters "github.com/smartcontractkit/chainlink-ccv/devenv/canton/adapters"
)

var (
	globalRegistry *adapters.ChainFamilyRegistry
	once           sync.Once
)

// GetGlobalChainFamilyRegistry returns the singleton global chain family registry
func GetGlobalChainFamilyRegistry() *adapters.ChainFamilyRegistry {
	once.Do(func() {
		globalRegistry = adapters.NewChainFamilyRegistry()

		// Init registers default adapters.
		// TODO: remove once chain-specific logic is moved to chain-specific repos
		globalRegistry.RegisterChainFamily(chain_selectors.FamilyEVM, &evmadapters.ChainFamilyAdapter{})
		globalRegistry.RegisterChainFamily(chain_selectors.FamilyCanton, cantonadapters.NewChainFamilyAdapter(&evmadapters.ChainFamilyAdapter{}))
	})

	return globalRegistry
}

// RegisterChainFamily registers a chain family adapter to the global registry.
func RegisterChainFamily(family string, adapter adapters.ChainFamily) {
	// If the family is already registered, check if the adapter is the same and avoid
	// registering it again.
	if _, isRegistered := globalRegistry.GetChainFamily(family); isRegistered {
		return
	}

	globalRegistry.RegisterChainFamily(family, adapter)
}
