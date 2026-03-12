package registry

import (
	"fmt"
	"sync"

	"github.com/Masterminds/semver/v3"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// Lombard destination token ref: same contract type/version/qualifier used when deploying Lombard tokens.
const (
	lombardTokenContractType = "BurnMintERC20WithDrip"
	lombardTokenVersion      = "1.7.0"
	lombardTokenQualifier    = "Lombard"
)

// LombardRegistry converts chain address strings to the 32-byte representation used by Lombard's
// SetAllowedDestinationToken(destinationToken bytes32). Each chain family (evm, canton, etc.) can
// register a converter.
type LombardRegistry struct {
	convertersMu sync.RWMutex
	converters   map[string]func(address string) ([32]byte, error)
}

// NewLombardRegistry returns a new LombardRegistry.
func NewLombardRegistry() *LombardRegistry {
	return &LombardRegistry{
		converters: make(map[string]func(address string) ([32]byte, error)),
	}
}

// DefaultLombardRegistry is the default registry used by devenv. Chain families register their
// converter in init() via RegisterConverter.
var DefaultLombardRegistry = NewLombardRegistry()

// RegisterConverter registers a converter for the given chain family (e.g. chain_selectors.FamilyEVM).
// It is typically called from init() of the chain's devenv package.
func (r *LombardRegistry) RegisterConverter(family string, fn func(address string) ([32]byte, error)) {
	r.convertersMu.Lock()
	defer r.convertersMu.Unlock()
	r.converters[family] = fn
}

// GetDestinationToken looks up the Lombard destination token address for the given chain from the
// datastore (using the Lombard token ref), then converts it to [32]byte using the converter for that chain's family.
func (r *LombardRegistry) GetDestinationToken(ds datastore.DataStore, chainSelector uint64) ([32]byte, error) {
	ref, err := ds.Addresses().Get(datastore.NewAddressRefKey(
		chainSelector,
		datastore.ContractType(lombardTokenContractType),
		semver.MustParse(lombardTokenVersion),
		lombardTokenQualifier,
	))
	if err != nil {
		return [32]byte{}, fmt.Errorf("get destination token address for chain %d: %w", chainSelector, err)
	}
	family, err := chain_selectors.GetSelectorFamily(chainSelector)
	if err != nil {
		return [32]byte{}, fmt.Errorf("get chain family for selector %d: %w", chainSelector, err)
	}
	r.convertersMu.RLock()
	fn, ok := r.converters[family]
	r.convertersMu.RUnlock()
	if !ok {
		return [32]byte{}, fmt.Errorf("no Lombard destination token converter registered for family %q (chain selector %d); register one via LombardRegistry.RegisterConverter", family, chainSelector)
	}
	return fn(ref.Address)
}
