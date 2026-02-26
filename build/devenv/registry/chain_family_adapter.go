package registry

import (
	"sync"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	evmadapters "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	cantonadapters "github.com/smartcontractkit/chainlink-ccv/build/devenv/canton/adapters"
)

var (
	globalChainFamilyAdapterRegistry *adapters.ChainFamilyRegistry
	chainFamilyAdapterOnce           sync.Once
)

// GetGlobalChainFamilyAdapterRegistry returns the singleton global chain family adapter registry.
func GetGlobalChainFamilyAdapterRegistry() *adapters.ChainFamilyRegistry {
	chainFamilyAdapterOnce.Do(func() {
		globalChainFamilyAdapterRegistry = adapters.NewChainFamilyRegistry()

		// Init registers default adapters.
		// TODO: remove once chain-specific logic is moved to chain-specific repos
		globalChainFamilyAdapterRegistry.RegisterChainFamily(chain_selectors.FamilyEVM, &evmadapters.ChainFamilyAdapter{})
		globalChainFamilyAdapterRegistry.RegisterChainFamily(chain_selectors.FamilyCanton, cantonadapters.NewChainFamilyAdapter(&evmadapters.ChainFamilyAdapter{}))
	})

	return globalChainFamilyAdapterRegistry
}

// RegisterChainFamilyAdapter registers a chain family adapter to the global registry.
// If the family is already registered, the call is a no-op.
func RegisterChainFamilyAdapter(family string, adapter adapters.ChainFamily) {
	// If the family is already registered, check if the adapter is the same and avoid
	// registering it again.
	if _, isRegistered := globalChainFamilyAdapterRegistry.GetChainFamily(family); isRegistered {
		return
	}

	globalChainFamilyAdapterRegistry.RegisterChainFamily(family, adapter)
}
