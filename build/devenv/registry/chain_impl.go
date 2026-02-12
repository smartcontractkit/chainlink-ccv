package registry

import (
	"fmt"
	"maps"
	"sync"

	chain_selectors "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
)

// ChainImplEntry holds a registered CCIP17 implementation along with its chain details.
type chainImplEntry struct {
	Impl    cciptestinterfaces.CCIP17
	Details chain_selectors.ChainDetails
}

// ChainImplRegistry holds registered CCIP17 chain implementations keyed by chain selector.
type ChainImplRegistry struct {
	mu    sync.RWMutex
	impls map[uint64]chainImplEntry
}

// Register registers a CCIP17 chain implementation for the given chain ID and family.
// The chain selector and details are derived from the chain ID and family.
// If an implementation is already registered for the derived selector, it will be replaced.
func (r *ChainImplRegistry) Register(chainID, family string, impl cciptestinterfaces.CCIP17) error {
	details, err := chain_selectors.GetChainDetailsByChainIDAndFamily(chainID, family)
	if err != nil {
		return fmt.Errorf("getting chain details for chain ID %s and family %s: %w", chainID, family, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.impls[details.ChainSelector] = chainImplEntry{Impl: impl, Details: details}
	return nil
}

// Get returns the CCIP17 implementation registered for the given chain selector.
func (r *ChainImplRegistry) Get(selector uint64) (cciptestinterfaces.CCIP17, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.impls[selector]
	return entry.Impl, ok
}

// GetAll returns a snapshot of all registered chain implementations
// as a map of chain selector to impl and details.
func (r *ChainImplRegistry) GetAll() map[uint64]chainImplEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[uint64]chainImplEntry, len(r.impls))
	maps.Copy(result, r.impls)
	return result
}

var (
	globalChainImplRegistry *ChainImplRegistry
	chainImplOnce           sync.Once
)

// GetGlobalChainImplRegistry returns the singleton global chain impl registry.
func GetGlobalChainImplRegistry() *ChainImplRegistry {
	chainImplOnce.Do(func() {
		globalChainImplRegistry = &ChainImplRegistry{
			impls: make(map[uint64]chainImplEntry),
		}
	})
	return globalChainImplRegistry
}
