package chainaccess

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"sync"
	"time"

	"github.com/BurntSushi/toml"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// AccessorFactoryConstructor creates an AccessorFactory for a specific chain family. When
// GetAccessor is called, it will delegate to the AccessorFactory corresponding to the chain
// family of the given chain selector.
type AccessorFactoryConstructor func(lggr logger.Logger, cfg GenericConfig) (AccessorFactory, error)

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

// Registry is the interface for obtaining chain Accessors by selector.
type Registry interface {
	// GetAccessor returns the Accessor for the given chain selector, or an error if no factory
	// is registered for the chain's family.
	GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (Accessor, error)
}

// registry is the concrete Registry backed by registered AccessorFactories.
type registry struct {
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
	ExecutorConfig
}

// GetAllConcreteConfig populates target, which must be a pointer to an Infos[T]
// (i.e. *map[string]T), with the decoded chain configs for every chain selector
// in ChainConfig that belongs to the given family. The map key is the chain
// selector formatted as a decimal string, matching the Infos key convention.
func (gc GenericConfig) GetAllConcreteConfig(family string, target any) error {
	rv := reflect.ValueOf(target)
	if rv.Kind() != reflect.Ptr || rv.Elem().Kind() != reflect.Map {
		return fmt.Errorf("GetAllConcreteConfig: target must be a pointer to a map, got %T", target)
	}
	if rv.Elem().Type().Key().Kind() != reflect.String {
		return fmt.Errorf("GetAllConcreteConfig: map key must be string (Infos[T] uses string keys), got %s", rv.Elem().Type().Key())
	}
	mapVal := rv.Elem()
	if mapVal.IsNil() {
		mapVal.Set(reflect.MakeMap(mapVal.Type()))
	}
	elemType := mapVal.Type().Elem()

	for _, sel := range gc.ChainConfig.GetAllChainSelectors() {
		fam, err := chainsel.GetSelectorFamily(uint64(sel))
		if err != nil {
			return fmt.Errorf("GetAllConcreteConfig: failed to get the chain selector family: %w", err)
		}
		if fam != family {
			continue
		}
		elem := reflect.New(elemType)
		if err := gc.GetConcreteConfig(sel, elem.Interface()); err != nil {
			return err
		}
		mapVal.SetMapIndex(reflect.ValueOf(sel.String()), elem.Elem())
	}
	return nil
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

	md, err := toml.Decode(string(data), target)
	if err != nil {
		return fmt.Errorf("failed to unmarshal info for selector '%s': %w", selector.String(), err)
	}
	if len(md.Undecoded()) > 0 {
		return fmt.Errorf("chain selector '%s' contains unknown fields: %v", selector.String(), md.Undecoded())
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

// DestinationChainConfig is the subset of per-chain executor configuration needed to construct
// a DestinationReader and ContractTransmitter. It is embedded in executor.ChainConfiguration so
// that the TOML field paths are identical in both the executor service config and the GenericConfig
// overlay read by the Registry.
type DestinationChainConfig struct {
	// OffRampAddress is the address of the OffRamp contract on the destination chain.
	OffRampAddress string `toml:"off_ramp_address"`
	// RmnAddress is the address of the RMN Remote contract on the destination chain.
	RmnAddress string `toml:"rmn_address"`
	// TransmitterKeyName is the name of the ECDSA key in the keystore used to sign and submit
	// transactions to the OffRamp on this chain. If empty, the EVM accessor defaults to
	// executor.DefaultEVMTransmitterKeyName.
	TransmitterKeyName string `toml:"transmitter_key_name"`
}

// ExecutorConfig is an overlay of the executor application configuration. It reads the subset of
// chain_configuration entries needed to construct DestinationReader and ContractTransmitter objects.
// The TOML key "chain_configuration" and per-chain field names must match exactly what the executor
// service parses (executor.ChainConfiguration embeds DestinationChainConfig for this reason).
//
// Example executor config shape mirrored here:
//
//	max_retry_duration = "8h"
//
//	[chain_configuration."<selector>"]
//	off_ramp_address = "0x..."
//	rmn_address      = "0x..."
//	# executor-only fields (executor_pool, execution_interval, etc.) are ignored by this overlay
type ExecutorConfig struct {
	// MaxRetryDuration is the maximum duration the executor cluster will retry a message before
	// giving up. It doubles as the ExecutionVisibilityWindow for the EvmDestinationReader, which
	// must look back at least this far to detect all honest execution attempts.
	MaxRetryDuration   time.Duration                     `toml:"max_retry_duration"`
	ChainConfiguration map[string]DestinationChainConfig `toml:"chain_configuration"`
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
func NewRegistry(lggr logger.Logger, config string) (Registry, error) {
	reg := registry{
		factories: make(map[ChainFamily]AccessorFactory),
	}

	var genericConfig GenericConfig
	if err := toml.Unmarshal([]byte(config), &genericConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal generic config: %w", err)
	}

	for family, constructor := range accessorConstructorMapCopy() {
		lggr.Infow("Constructing accessor factory for chain family", "family", family)
		accessor, err := constructor(lggr, genericConfig)
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
func (r *registry) GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (Accessor, error) {
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
