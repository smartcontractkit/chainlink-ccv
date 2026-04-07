package chainaccess

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/BurntSushi/toml"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// AccessorFactoryConstructor creates an AccessorFactory for a specific chain family. When
// GetAccessor is called, it will delegate to the AccessorFactory corresponding to the chain
// family of the given chain selector.
type AccessorFactoryConstructor func(lggr logger.Logger, cfg string) (AccessorFactory, error)

type ChainFamily string

var (
	accessorConstructorMap      = make(map[ChainFamily]AccessorFactoryConstructor)
	accessorConstructorMapMutex sync.RWMutex
)

// Register an accessor factory constructor.
func Register(name ChainFamily, constructor AccessorFactoryConstructor) {
	accessorConstructorMapMutex.Lock()
	defer accessorConstructorMapMutex.Unlock()

	if _, ok := accessorConstructorMap[name]; ok {
		panic(fmt.Sprintf("accessor constructor with name %s already exists", name))
	}

	accessorConstructorMap[name] = constructor
}

// Registry holds AccessorFactories for different chain families.
type Registry struct {
	factories map[ChainFamily]AccessorFactory
}

// GenericConfig is an overlay of the app configuration. All configuration needed to construct the accessor
// should be included here. Note that the Committee Configs are present, they must map to the same location
// that they appear when parsing just the committee config file:
//
//	type ConfigWithBlockchainInfos struct {
//	    Config
//	    BlockchainInfos map[string]any `toml:"blockchain_infos"`
//	}
//
//	type Config struct {
//	    ...
//	    // OnRampAddresses is a map the addresses of the on ramps for each chain selector.
//	    OnRampAddresses map[string]string `toml:"on_ramp_addresses"`
//	    // RMNRemoteAddresses is a map of RMN Remote contract addresses for each chain selector.
//	    // Required for curse detection.
//	    RMNRemoteAddresses map[string]string `toml:"rmn_remote_addresses"`
//	    // DisableFinalityCheckers is a list of chain selectors for which the finality violation checker should be disabled.
//	    // The chain selectors are formatted as strings of the chain selector.
//	}
//
// TODO: Use protocol.Selector instead of string for all the map[string].
type GenericConfig struct {
	// ChainConfig is parsed by the concrete implementation.
	ChainConfig Infos[any] `toml:"blockchain_infos"`

	CommitteeConfig
}

func (gc GenericConfig) GetConcreteConfig(selector protocol.ChainSelector, target any) error {
	info, ok := gc.ChainConfig[selector.String()]
	if !ok {
		return fmt.Errorf("chain selector '%s' not found", selector.String())
	}
	data, err := toml.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal info for selector '%s': %w", selector.String(), err)
	}

	_, err = toml.Decode(string(data), target)
	if err != nil {
		return fmt.Errorf("failed to unmarshal info for selector '%s': %w", selector.String(), err)
	}
	return nil
}

// CommitteeConfig that is defined as part of the app and required by the SourceReader.
type CommitteeConfig struct {
	// OnRampAddresses is a map the addresses of the on ramps for each chain selector.
	OnRampAddresses map[string]string `json:"on_ramp_addresses" toml:"on_ramp_addresses"`

	// RMNRemoteAddresses is a map of RMN Remote contract addresses for each chain selector.
	// Required for curse detection.
	RMNRemoteAddresses map[string]string `json:"rmn_remote_addresses" toml:"rmn_remote_addresses"`
}

// accessorConstructorMapCopy returns a copy of the accessorConstructorMap to avoid holding the lock during
// delegate calls.
func accessorConstructorMapCopy() map[ChainFamily]AccessorFactoryConstructor {
	accessorConstructorMapMutex.Lock()
	defer accessorConstructorMapMutex.Unlock()
	constructorCopy := make(map[ChainFamily]AccessorFactoryConstructor)
	maps.Copy(constructorCopy, accessorConstructorMap)
	return constructorCopy
}

// NewRegistry creates a new Registry with some configuration.
func NewRegistry(lggr logger.Logger, config string) (AccessorFactory, error) {
	reg := Registry{
		factories: make(map[ChainFamily]AccessorFactory),
	}

	for family, constructor := range accessorConstructorMapCopy() {
		accessor, err := constructor(lggr, config)
		if err != nil {
			return nil, fmt.Errorf("failed to construct accessor factory for family %s: %w", family, err)
		}
		reg.factories[family] = accessor
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

	factory, ok := r.factories[ChainFamily(family)]
	if !ok {
		return nil, fmt.Errorf("no factory registered for chain family %s (%d)", family, chainSelector)
	}

	return factory.GetAccessor(ctx, chainSelector)
}
