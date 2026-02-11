package registry

import (
	"fmt"
	"sync"

	chain_selectors "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
)

// ChainImplEntry holds a registered CCIP17 implementation along with its chain details.
type ChainImplEntry struct {
	Impl    cciptestinterfaces.CCIP17
	Details chain_selectors.ChainDetails
}

var (
	chainImpls   = make(map[uint64]ChainImplEntry)
	chainImplsMu sync.RWMutex
)

// RegisterChainImpl registers a CCIP17 chain implementation for the given chain ID and family.
// The chain selector and details are derived from the chain ID and family.
// If an implementation is already registered for the derived selector, it will be replaced.
func RegisterChainImpl(chainID, family string, impl cciptestinterfaces.CCIP17) error {
	details, err := chain_selectors.GetChainDetailsByChainIDAndFamily(chainID, family)
	if err != nil {
		return fmt.Errorf("getting chain details for chain ID %s and family %s: %w", chainID, family, err)
	}
	chainImplsMu.Lock()
	defer chainImplsMu.Unlock()
	chainImpls[details.ChainSelector] = ChainImplEntry{Impl: impl, Details: details}
	return nil
}

// GetChainImpl returns the CCIP17 implementation registered for the given chain selector.
func GetChainImpl(selector uint64) (cciptestinterfaces.CCIP17, bool) {
	chainImplsMu.RLock()
	defer chainImplsMu.RUnlock()
	entry, ok := chainImpls[selector]
	return entry.Impl, ok
}

// GetAllChainImpls returns a snapshot of all registered chain implementations
// as a map of chain selector to impl and details.
func GetAllChainImpls() map[uint64]ChainImplEntry {
	chainImplsMu.RLock()
	defer chainImplsMu.RUnlock()
	result := make(map[uint64]ChainImplEntry, len(chainImpls))
	for k, v := range chainImpls {
		result[k] = v
	}
	return result
}
