package chainaccess

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
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
	closeOnce sync.Once
	closeErr  error
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
			// A constructor may return a partially initialized factory alongside an error.
			// Include it in cleanup so every resource allocated before this failure is released.
			if accessor != nil {
				reg.factories[family] = accessor
			}
			constructionErr := fmt.Errorf("failed to construct accessor factory for family %s: %w", family, err)
			if closeErr := reg.Close(); closeErr != nil {
				return nil, errors.Join(constructionErr, fmt.Errorf("close partial registry: %w", closeErr))
			}
			return nil, constructionErr
		}
		reg.factories[family] = accessor
	}

	return &reg, nil
}

// Close releases resources owned by accessor factories that opt into terminal cleanup by
// implementing io.Closer. Close is idempotent. It is deliberately an optional extension to
// Registry so downstream registry implementations do not need to change.
func (r *registry) Close() error {
	r.closeOnce.Do(func() {
		var errs []error
		for family, factory := range r.factories {
			closer, ok := factory.(io.Closer)
			if !ok {
				continue
			}
			if err := closer.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close accessor factory for family %s: %w", family, err))
			}
		}
		r.closeErr = errors.Join(errs...)
	})
	return r.closeErr
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
