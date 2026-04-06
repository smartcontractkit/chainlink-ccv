package chainaccess

import (
	"context"
	"fmt"
	"sync"

	"github.com/BurntSushi/toml"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type AccessorFactoryConstructor func(lggr logger.Logger, cfg string) (AccessorFactory, error)

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
// TODO: Use protocol.Selector instead of string.
type GenericConfig struct {
	// ChainConfig is parsed by the concrete implementation.
	ChainConfig Infos[string] `toml:"blockchain_infos"`

	CommitteeConfig
}

// CommitteeConfig that is defined as part of the app and required by the SourceReader.
type CommitteeConfig struct {
	// OnRampAddresses is a map the addresses of the on ramps for each chain selector.
	OnRampAddresses map[string]string `toml:"on_ramp_addresses"`

	// RMNRemoteAddresses is a map of RMN Remote contract addresses for each chain selector.
	// Required for curse detection.
	RMNRemoteAddresses map[string]string `toml:"rmn_remote_addresses"`
}

// NewRegistry creates a new Registry with some configuration.
func NewRegistry(lggr logger.Logger, config string) (AccessorFactory, error) {
	var genericConfig GenericConfig
	_, err := toml.Decode(config, &genericConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing config: %s", err)
	}

	reg := Registry{
		factories: make(map[string]AccessorFactory),
	}

	for family := range genericConfig.ChainConfig {
		constructor, ok := accessorConstructorMap[family]
		if !ok {
			return nil, fmt.Errorf("configuration found for unknown accessor factory type: %s", family)
		}
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

	factory, ok := r.factories[family]
	if !ok {
		return nil, fmt.Errorf("no factory registered for chain family %s (%d)", family, chainSelector)
	}

	return factory.GetAccessor(ctx, chainSelector)
}
