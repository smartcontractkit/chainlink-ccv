package chainaccess

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// AccessorFactoryConstructor creates an AccessorFactory for a specific chain family. When
// GetAccessor is called, it will delegate to the AccessorFactory corresponding to the chain
// family of the given chain selector.
type AccessorFactoryConstructor func(lggr logger.Logger, cfg GenericConfig) (AccessorFactory, error)

// DataSourceSetter is an optional hook an AccessorFactory can implement to receive the bootstrap
// database. NewRegistry calls it on every factory that implements it, after construction and
// before the Registry is returned, so a factory always has the handle before its first
// GetAccessor. Factories that do not implement it are left alone.
//
// It is a hook on the factory rather than a parameter on AccessorFactoryConstructor because chain
// families live in their own repos (chainlink-canton, chainlink-ccip-solana) and register through
// that signature. Widening it would break each of them on their next dependency bump, to hand them
// something they have no use for: both derive head and finality state from their RPC on every call
// and hold no durable state.
//
// It is also a hook on the factory rather than on the Accessor, which is how the keystore arrives
// (see bootstrap.KeystoreSetter). A family may need the handle while building the services an
// Accessor wraps, so it has to be available before GetAccessor rather than after. The EVM accessor
// builds its head tracker there, and the tracker's persistence is fixed when it is created.
//
// The handle maps Go struct fields to columns as snake_case, which is what chainlink-evm's and
// chainlink-core's ORMs expect from row structs that carry no db tags.
//
// Implementations should treat the call as part of construction: it happens once, on one
// goroutine, before the factory is used.
type DataSourceSetter interface {
	// SetDataSource provides the bootstrap database. It is only called with a non-nil handle; a
	// factory that is never called runs without durable state and is expected to fall back to an
	// in-memory equivalent rather than fail.
	//
	// Tables live in a schema per family, created by bootstrap/db/migrations, which runs on
	// connect, so a family can assume its own schema is present.
	SetDataSource(ds sqlutil.DataSource)
}

// RegistryOption configures the Registry built by NewRegistry.
type RegistryOption func(*registryOptions)

type registryOptions struct {
	dataSource sqlutil.DataSource
}

// WithDataSource shares a database handle with every accessor factory that implements
// DataSourceSetter. Omitting it means no factory is given one, which each family reads as "run
// without durable state".
func WithDataSource(ds sqlutil.DataSource) RegistryOption {
	return func(o *registryOptions) {
		o.dataSource = ds
	}
}

type ChainFamily string

// BlockchainInfosConfigKey is the removed application-config field retained only so stale job
// specs can be detected and ignored during rollout.
const BlockchainInfosConfigKey = "blockchain_infos"

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

// GenericConfig is the overlay of application-owned settings shared with accessor constructors.
// Fields must map to the same TOML locations used by each application's typed config. Chain
// connection and tuning details come from chain-family local config in standalone mode or node
// config in CL mode.
// TODO: Use protocol.Selector instead of string for all the map[string].
type GenericConfig struct {
	CommitteeConfig
	ExecutorConfig
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
	// TransmitterKeyName is the family-specific keystore key name used to sign and submit
	// transactions to the OffRamp on this chain. If empty, accessors fall back to their
	// family's default transmitter key (defined by each family's transmitter package).
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

// NewRegistry creates a new Registry with some configuration. Options supply the runtime handles
// shared with every family's constructor; see Deps.
func NewRegistry(lggr logger.Logger, config string, opts ...RegistryOption) (Registry, error) {
	reg := registry{
		factories: make(map[ChainFamily]AccessorFactory),
	}

	var options registryOptions
	for _, opt := range opts {
		opt(&options)
	}

	var genericConfig GenericConfig
	md, err := toml.Decode(config, &genericConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal generic config: %w", err)
	}
	for _, key := range md.Keys() {
		if len(key) > 0 && strings.EqualFold(key[0], BlockchainInfosConfigKey) {
			lggr.Warnw("Ignoring removed application config; use chain-family local or node config", "field", BlockchainInfosConfigKey)
			break
		}
	}

	for family, constructor := range accessorConstructorMapCopy() {
		lggr.Infow("Constructing accessor factory for chain family", "family", family)
		accessor, err := constructor(lggr, genericConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to construct accessor factory for family %s: %w", family, err)
		}
		if options.dataSource != nil {
			if setter, ok := accessor.(DataSourceSetter); ok {
				setter.SetDataSource(options.dataSource)
				lggr.Infow("Shared the bootstrap database with accessor factory", "family", family)
			}
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
