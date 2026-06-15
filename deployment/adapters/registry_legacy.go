package adapters

import (
	"fmt"
	"sync"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// NOTE (topology-free deploy / flatten-registration coordination):
// This file restores the legacy bundled-registration API (Registry +
// ChainAdapters + GetRegistry) alongside the per-type FamilyRegistry getters in
// registry.go. It exists so this branch keeps compiling against chainlink-ccip
// MAIN, whose chains/evm adapter init.go still registers via
// GetRegistry().Register(family, ChainAdapters{...}).
//
// Landing sequence: (1) this PR ships on chainlink-ccip main with both APIs;
// (2) chainlink-ccip #2084 ("flatten registration") repoints at this ccv and
// switches its init.go to the per-type getters; (3) this ccv repoints at the
// post-#2084 chainlink-ccip main and DELETES this file (the actual flatten).

// ChainAdapters bundles all chain-family-specific adapter implementations.
// A nil field means the adapter is not supported for that family.
type ChainAdapters struct {
	Aggregator               AggregatorConfigAdapter
	Executor                 ExecutorConfigAdapter
	Verifier                 VerifierConfigAdapter
	Indexer                  IndexerConfigAdapter
	TokenVerifier            TokenVerifierConfigAdapter
	CommitteeVerifierOnchain CommitteeVerifierOnchainAdapter
	CommitteeVerifierDeploy  CommitteeVerifierDeployAdapter
}

// Registry is a single registry mapping chain family → ChainAdapters.
// Use GetRegistry() to obtain the process-wide singleton.
type Registry struct {
	mu       sync.Mutex
	adapters map[string]ChainAdapters
}

var (
	singletonRegistry *Registry
	registryOnce      sync.Once
)

func GetRegistry() *Registry {
	registryOnce.Do(func() {
		singletonRegistry = &Registry{
			adapters: make(map[string]ChainAdapters),
		}
	})
	return singletonRegistry
}

// Register merges a into the existing ChainAdapters for the given family.
// Non-nil fields in a overwrite the corresponding field in the existing entry;
// nil fields leave the existing value unchanged. This allows separate packages
// (e.g. ccip for onchain adapters, ccv/evm for offchain adapters) to each
// register their piece independently without conflicting.
func (r *Registry) Register(family string, a ChainAdapters) {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing := r.adapters[family]
	if a.Aggregator != nil {
		existing.Aggregator = a.Aggregator
	}
	if a.Executor != nil {
		existing.Executor = a.Executor
	}
	if a.Verifier != nil {
		existing.Verifier = a.Verifier
	}
	if a.Indexer != nil {
		existing.Indexer = a.Indexer
	}
	if a.TokenVerifier != nil {
		existing.TokenVerifier = a.TokenVerifier
	}
	if a.CommitteeVerifierOnchain != nil {
		existing.CommitteeVerifierOnchain = a.CommitteeVerifierOnchain
	}
	if a.CommitteeVerifierDeploy != nil {
		existing.CommitteeVerifierDeploy = a.CommitteeVerifierDeploy
	}
	r.adapters[family] = existing
}

func (r *Registry) Get(family string) (ChainAdapters, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.adapters[family]
	return a, ok
}

func (r *Registry) GetByChain(chainSelector uint64) (ChainAdapters, error) {
	family, err := chainsel.GetSelectorFamily(chainSelector)
	if err != nil {
		return ChainAdapters{}, fmt.Errorf("failed to get chain family for selector %d: %w", chainSelector, err)
	}
	a, ok := r.Get(family)
	if !ok {
		return ChainAdapters{}, fmt.Errorf("no adapters registered for chain family %q", family)
	}
	return a, nil
}

// AllDeployedCommitteeVerifierChainsLegacy returns every destination chain selector that has a
// committee verifier deployed for the given qualifier, across all registered chain families.
// Discovery is datastore-only — no onchain calls are made. The per-family implementation
// (e.g. EVM) lives in chainlink-ccip/chains/evm and registers via Register at startup.
func (r *Registry) AllDeployedCommitteeVerifierChains(ds datastore.DataStore, qualifier string) []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var chains []uint64
	for _, a := range r.adapters {
		if a.Aggregator != nil {
			chains = append(chains, a.Aggregator.GetDeployedChains(ds, qualifier)...)
		}
	}
	return chains
}

// AllDeployedExecutorChains collects all chain selectors with executor proxies deployed,
// across all registered families.
func (r *Registry) AllDeployedExecutorChains(ds datastore.DataStore, qualifier string) []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var chains []uint64
	for _, a := range r.adapters {
		if a.Executor != nil {
			chains = append(chains, a.Executor.GetDeployedChains(ds, qualifier)...)
		}
	}
	return chains
}

// HasAdapters reports whether any chain family has been registered.
func (r *Registry) HasAdapters() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.adapters) > 0
}
