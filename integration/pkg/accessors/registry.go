package accessors

import (
	"context"
	"fmt"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// Registry holds AccessorFactories for different chain families.
type Registry struct {
	factories map[string]chainaccess.AccessorFactory
}

// NewRegistry creates a new Registry.
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]chainaccess.AccessorFactory),
	}
}

// Register registers an AccessorFactory for a given chain family.
// It overwrites any existing factory for the same chain family.
// Not concurrent safe.
func (r *Registry) Register(family string, factory chainaccess.AccessorFactory) {
	r.factories[family] = factory
}

// GetAccessor creates an Accessor for the given chain selector using the registered AccessorFactory.
// It returns an error if no factory is registered for the chain family.
// Not concurrent safe.
func (r *Registry) GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (chainaccess.Accessor, error) {
	family, err := chainsel.GetSelectorFamily(uint64(chainSelector))
	if err != nil {
		return nil, fmt.Errorf("failed to get selector family for chain %d - update chain-selectors library?: %w", chainSelector, err)
	}

	factory, ok := r.factories[family]
	if !ok {
		return nil, fmt.Errorf("no factory registered for chain family %s (%d)", family, chainSelector)
	}

	return factory.GetAccessor(ctx, chainSelector)
}
