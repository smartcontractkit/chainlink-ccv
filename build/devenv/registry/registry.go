// Package registry provides a global chain family registry that can be used
// across packages without creating import cycles.
package registry

import (
	"sync"

	evmadapters "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	cantonadapters "github.com/smartcontractkit/chainlink-ccv/devenv/canton/adapters"
)

// ChainFamily is the interface that chain family adapters must implement.
type ChainFamily = adapters.ChainFamily

var (
	globalRegistry     *adapters.ChainFamilyRegistry
	globalRegistryOnce sync.Once
)

// GetGlobalChainFamilyRegistry returns the global chain family registry singleton.
func GetGlobalChainFamilyRegistry() *adapters.ChainFamilyRegistry {
	globalRegistryOnce.Do(func() {
		globalRegistry = adapters.NewChainFamilyRegistry()
		// Register default adapters
		// TODO: remove once chain-specific logic is moved to chain-specific repos
		globalRegistry.RegisterChainFamily("evm", &evmadapters.ChainFamilyAdapter{})
		globalRegistry.RegisterChainFamily("canton", cantonadapters.NewChainFamilyAdapter(&evmadapters.ChainFamilyAdapter{}))
	})
	return globalRegistry
}

// RegisterChainFamily registers a chain family adapter to the global registry.
func RegisterChainFamily(family string, adapter ChainFamily) {
	GetGlobalChainFamilyRegistry().RegisterChainFamily(family, adapter)
}
