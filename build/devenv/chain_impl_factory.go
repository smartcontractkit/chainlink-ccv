package ccv

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// ImplFactory is a factory for creating CCIP17 implementations.
type ImplFactory interface {
	// NewEmpty creates an empty cciptestinterfaces.CCIP17Configuration object, this is
	// primarily used to spin up new environments.
	NewEmpty() cciptestinterfaces.CCIP17Configuration
	// New creates a new cciptestinterfaces.CCIP17 object, this is primarily used in
	// tests.
	New(
		ctx context.Context,
		cfg *Cfg,
		lggr zerolog.Logger,
		env *deployment.Environment,
		bc *blockchain.Input,
	) (cciptestinterfaces.CCIP17, error)
}

var (
	// implFactories is a map of chain family to implementation factory.
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
