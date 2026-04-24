package shared

import (
	"sync"

	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

var (
	chainTypeMu       sync.RWMutex
	chainTypeRegistry = make(map[nodev1.ChainType]string)

	normalizerMu       sync.RWMutex
	normalizerRegistry = make(map[string]func(string) string)
)

// RegisterChainTypeFamily maps a JD proto ChainType to its chain-selectors family string.
// Chain-specific packages (e.g. evm) call this from their init() function so that JD
// operations can filter chain configs without hardcoding known families in the core.
func RegisterChainTypeFamily(protoType nodev1.ChainType, family string) {
	chainTypeMu.Lock()
	defer chainTypeMu.Unlock()
	chainTypeRegistry[protoType] = family
}

// GetChainTypeFamily returns the chain-selectors family string for the given JD proto ChainType.
// Returns false if no chain-specific package has registered a mapping for this type.
func GetChainTypeFamily(protoType nodev1.ChainType) (string, bool) {
	chainTypeMu.RLock()
	defer chainTypeMu.RUnlock()
	f, ok := chainTypeRegistry[protoType]
	return f, ok
}

// RegisterAddressNormalizer registers a chain-family-specific function that canonicalises
// raw signing addresses returned by JD (e.g. lowercase + "0x" prefix for EVM).
// If no normalizer is registered for a family the address is used as-is.
func RegisterAddressNormalizer(family string, fn func(string) string) {
	normalizerMu.Lock()
	defer normalizerMu.Unlock()
	normalizerRegistry[family] = fn
}

// NormalizeAddress returns the canonical form of addr for the given chain family.
// Falls back to the identity function when no normalizer has been registered.
func NormalizeAddress(family, addr string) string {
	normalizerMu.RLock()
	fn, ok := normalizerRegistry[family]
	normalizerMu.RUnlock()
	if !ok {
		return addr
	}
	return fn(addr)
}
