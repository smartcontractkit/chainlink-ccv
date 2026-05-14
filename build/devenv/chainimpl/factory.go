// Package chainimpl holds the per-chain CCIP17 implementation factory
// registry. It lives in its own package so callers below the ccv package
// (e.g. phased-runtime components) can resolve chain implementations without
// importing the ccv package and creating an import cycle.
package chainimpl

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// ImplFactory is a factory for creating CCIP17 implementations.
// Product repos (chainlink-canton, chainlink-stellar, chainlink-ccip-solana)
// implement this interface and register via RegisterImplFactory in their init().
type ImplFactory interface {
	// NewEmpty creates an empty cciptestinterfaces.CCIP17Configuration object, this is
	// primarily used to spin up new environments.
	NewEmpty() cciptestinterfaces.CCIP17Configuration
	// New creates a new cciptestinterfaces.CCIP17 object, this is primarily used in
	// tests.
	New(
		ctx context.Context,
		lggr zerolog.Logger,
		env *deployment.Environment,
		bc *blockchain.Input,
	) (cciptestinterfaces.CCIP17, error)

	// DefaultSignerKey returns the default signer key for this chain family
	// given the bootstrap keys from a verifier node. Each family selects the
	// appropriate key type (e.g. EVM uses ECDSAAddress, Stellar uses EdDSA).
	// Return "" if no default signer is available.
	DefaultSignerKey(keys services.BootstrapKeys) string

	// DefaultFeeAggregator returns a fee aggregator address to use as a
	// fallback when topology omits one for the given chain. Each family
	// extracts the deployer address in its native format from the environment.
	// Return "" if no fallback is available for the given selector.
	DefaultFeeAggregator(env *deployment.Environment, chainSelector uint64) string

	// SupportsFunding reports whether this chain family supports native token
	// funding of executor addresses. Families that lack on-chain transfer
	// primitives in devenv (e.g. Canton) return false.
	SupportsFunding() bool
}

var (
	implFactories   map[string]ImplFactory
	implFactoriesMu sync.Mutex
)

func init() {
	implFactories = make(map[string]ImplFactory)
}

// RegisterImplFactory registers a new implementation factory for a given chain family.
// If the family is already registered, the call is a no-op.
func RegisterImplFactory(family string, factory ImplFactory) {
	implFactoriesMu.Lock()
	defer implFactoriesMu.Unlock()
	if _, ok := implFactories[family]; ok {
		return
	}
	implFactories[family] = factory
}

// GetImplFactory returns the implementation factory for a given chain family.
func GetImplFactory(family string) (ImplFactory, error) {
	implFactoriesMu.Lock()
	defer implFactoriesMu.Unlock()
	fac, ok := implFactories[family]
	if !ok {
		return nil, fmt.Errorf("implementation factory for family %s not found", family)
	}
	return fac, nil
}

// GetAllImplFactories returns a snapshot of all registered implementation factories.
func GetAllImplFactories() map[string]ImplFactory {
	implFactoriesMu.Lock()
	defer implFactoriesMu.Unlock()
	result := make(map[string]ImplFactory, len(implFactories))
	maps.Copy(result, implFactories)
	return result
}
