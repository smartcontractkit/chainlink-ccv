package adapters

import (
	"fmt"
	"sync"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// --------------------------------------------------------------------
// Generic per-family registry
// --------------------------------------------------------------------

// FamilyRegistry is a simple per-chain-family adapter registry.
// Each adapter interface gets its own singleton FamilyRegistry[T].
type FamilyRegistry[T any] struct {
	mu       sync.Mutex
	adapters map[string]T // family → adapter
}

func newFamilyRegistry[T any]() *FamilyRegistry[T] {
	return &FamilyRegistry[T]{adapters: make(map[string]T)}
}

// Register sets the adapter for the given chain family.
func (r *FamilyRegistry[T]) Register(family string, adapter T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adapters[family] = adapter
}

// Get returns the adapter registered for the chain that owns chainSelector.
func (r *FamilyRegistry[T]) Get(chainSelector uint64) (T, error) {
	family, err := chainsel.GetSelectorFamily(chainSelector)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("failed to get chain family for selector %d: %w", chainSelector, err)
	}
	r.mu.Lock()
	v, ok := r.adapters[family]
	r.mu.Unlock()
	if !ok {
		var zero T
		return zero, fmt.Errorf("no adapter registered for chain family %q (selector %d)", family, chainSelector)
	}
	return v, nil
}

// ForEach calls fn for every registered adapter. Intended for cross-family
// discovery (e.g. AllDeployedCommitteeVerifierChains).
func (r *FamilyRegistry[T]) ForEach(fn func(family string, adapter T)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for f, a := range r.adapters {
		fn(f, a)
	}
}

// IsEmpty reports whether any adapter has been registered.
func (r *FamilyRegistry[T]) IsEmpty() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.adapters) == 0
}

// --------------------------------------------------------------------
// Per-adapter-type singletons
// --------------------------------------------------------------------

var (
	aggregatorRegistry               *FamilyRegistry[AggregatorConfigAdapter]
	aggregatorOnce                   sync.Once
	executorRegistry                 *FamilyRegistry[ExecutorConfigAdapter]
	executorOnce                     sync.Once
	verifierRegistry                 *FamilyRegistry[VerifierConfigAdapter]
	verifierOnce                     sync.Once
	indexerRegistry                  *FamilyRegistry[IndexerConfigAdapter]
	indexerOnce                      sync.Once
	tokenVerifierRegistry            *FamilyRegistry[TokenVerifierConfigAdapter]
	tokenVerifierOnce                sync.Once
	committeeVerifierOnchainRegistry *FamilyRegistry[CommitteeVerifierOnchainAdapter]
	committeeVerifierOnchainOnce     sync.Once
	committeeVerifierDeployRegistry  *FamilyRegistry[CommitteeVerifierDeployAdapter]
	committeeVerifierDeployOnce      sync.Once
	laneConfigRegistry               *FamilyRegistry[LaneConfigAdapter]
	laneConfigOnce                   sync.Once
	protocolContractsDeployRegistry  *FamilyRegistry[ProtocolContractsDeployAdapter]
	protocolContractsDeployOnce      sync.Once
)

func GetAggregatorRegistry() *FamilyRegistry[AggregatorConfigAdapter] {
	aggregatorOnce.Do(func() { aggregatorRegistry = newFamilyRegistry[AggregatorConfigAdapter]() })
	return aggregatorRegistry
}

func GetExecutorRegistry() *FamilyRegistry[ExecutorConfigAdapter] {
	executorOnce.Do(func() { executorRegistry = newFamilyRegistry[ExecutorConfigAdapter]() })
	return executorRegistry
}

func GetVerifierRegistry() *FamilyRegistry[VerifierConfigAdapter] {
	verifierOnce.Do(func() { verifierRegistry = newFamilyRegistry[VerifierConfigAdapter]() })
	return verifierRegistry
}

func GetIndexerRegistry() *FamilyRegistry[IndexerConfigAdapter] {
	indexerOnce.Do(func() { indexerRegistry = newFamilyRegistry[IndexerConfigAdapter]() })
	return indexerRegistry
}

func GetTokenVerifierRegistry() *FamilyRegistry[TokenVerifierConfigAdapter] {
	tokenVerifierOnce.Do(func() { tokenVerifierRegistry = newFamilyRegistry[TokenVerifierConfigAdapter]() })
	return tokenVerifierRegistry
}

func GetCommitteeVerifierOnchainRegistry() *FamilyRegistry[CommitteeVerifierOnchainAdapter] {
	committeeVerifierOnchainOnce.Do(func() { committeeVerifierOnchainRegistry = newFamilyRegistry[CommitteeVerifierOnchainAdapter]() })
	return committeeVerifierOnchainRegistry
}

func GetCommitteeVerifierDeployRegistry() *FamilyRegistry[CommitteeVerifierDeployAdapter] {
	committeeVerifierDeployOnce.Do(func() { committeeVerifierDeployRegistry = newFamilyRegistry[CommitteeVerifierDeployAdapter]() })
	return committeeVerifierDeployRegistry
}

func GetLaneConfigRegistry() *FamilyRegistry[LaneConfigAdapter] {
	laneConfigOnce.Do(func() { laneConfigRegistry = newFamilyRegistry[LaneConfigAdapter]() })
	return laneConfigRegistry
}

func GetProtocolContractsDeployRegistry() *FamilyRegistry[ProtocolContractsDeployAdapter] {
	protocolContractsDeployOnce.Do(func() { protocolContractsDeployRegistry = newFamilyRegistry[ProtocolContractsDeployAdapter]() })
	return protocolContractsDeployRegistry
}

// --------------------------------------------------------------------
// Cross-family discovery helpers
// --------------------------------------------------------------------

// AllDeployedCommitteeVerifierChains returns every chain selector that has a
// committee verifier deployed for the given qualifier, across all families.
func AllDeployedCommitteeVerifierChains(ds datastore.DataStore, qualifier string) []uint64 {
	var chains []uint64
	GetAggregatorRegistry().ForEach(func(_ string, a AggregatorConfigAdapter) {
		chains = append(chains, a.GetDeployedChains(ds, qualifier)...)
	})
	return chains
}

// AllDeployedExecutorChains returns every chain selector with executor proxies
// deployed, across all families.
func AllDeployedExecutorChains(ds datastore.DataStore, qualifier string) []uint64 {
	var chains []uint64
	GetExecutorRegistry().ForEach(func(_ string, a ExecutorConfigAdapter) {
		chains = append(chains, a.GetDeployedChains(ds, qualifier)...)
	})
	return chains
}
