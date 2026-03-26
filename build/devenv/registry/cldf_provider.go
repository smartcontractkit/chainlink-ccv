package registry

import (
	"context"
	"sync"

	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// CLDFProviderFactory creates an initialized CLDF BlockChain provider from the
// given blockchain input. It returns the provider and its chain selector.
type CLDFProviderFactory func(ctx context.Context, b *blockchain.Input) (cldf_chain.BlockChain, uint64, error)

// CLDFProviderRegistry holds registered CLDF provider factories keyed by chain family.
type CLDFProviderRegistry struct {
	mu        sync.RWMutex
	factories map[string]CLDFProviderFactory
}

// Register registers a CLDFProviderFactory for the given chain family.
// If a factory is already registered for the family, the call is a no-op.
func (r *CLDFProviderRegistry) Register(family string, factory CLDFProviderFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.factories[family]; ok {
		return
	}
	r.factories[family] = factory
}

// Get returns the CLDFProviderFactory registered for the given chain family.
func (r *CLDFProviderRegistry) Get(family string) (CLDFProviderFactory, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.factories[family]
	return f, ok
}

var (
	globalCLDFProviderRegistry *CLDFProviderRegistry
	cldfProviderOnce           sync.Once
)

// GetGlobalCLDFProviderRegistry returns the singleton global CLDF provider registry.
func GetGlobalCLDFProviderRegistry() *CLDFProviderRegistry {
	cldfProviderOnce.Do(func() {
		globalCLDFProviderRegistry = &CLDFProviderRegistry{
			factories: make(map[string]CLDFProviderFactory),
		}
	})
	return globalCLDFProviderRegistry
}

// RegisterCLDFProviderFactory registers a CLDF provider factory for the given
// chain family in the global registry. If the family is already registered,
// the call is a no-op.
func RegisterCLDFProviderFactory(family string, factory CLDFProviderFactory) {
	GetGlobalCLDFProviderRegistry().Register(family, factory)
}
