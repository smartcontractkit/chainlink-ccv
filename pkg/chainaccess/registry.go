package chainaccess

import (
	"context"
	"fmt"
	"sync"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type AccessorFactoryConstructor func(cfg string) AccessorFactory

var (
	accessorConstructorMap      = make(map[string]AccessorFactoryConstructor)
	accessorConstructorMapMutex sync.RWMutex
)

// Register an accessor factory constructor.
func Register(name string, constructor AccessorFactoryConstructor) {
	accessorConstructorMapMutex.Lock()
	defer accessorConstructorMapMutex.Unlock()

	if _, ok := accessorConstructorMap[name]; ok {
		panic(fmt.Sprintf("accessor constructor with name %s already exists", name))
	}

	accessorConstructorMap[name] = constructor
}

// Registry holds AccessorFactories for different chain families.
type Registry struct {
	factories map[string]AccessorFactory
}

// NewRegistry creates a new Registry with some configuration.
func NewRegistry(config map[string]string) (*Registry, error) {
	reg := Registry{
		factories: make(map[string]AccessorFactory),
	}

	for family, cfg := range config {
		constructor, ok := accessorConstructorMap[family]
		if !ok {
			return nil, fmt.Errorf("configuration found for unknown accessor factory type: %s", family)
		}
		reg.factories[family] = constructor(cfg)
	}

	return &reg, nil
}

// GetAccessor creates an Accessor for the given chain selector using the registered AccessorFactory.
// It returns an error if no factory is registered for the chain family.
// Not concurrent safe.
func (r *Registry) GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (Accessor, error) {
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
