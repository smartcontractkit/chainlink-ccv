package ccv

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	chain_selectors "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// NewCCIP17ForChainSelector builds a CCIP17 implementation for the given selector using the
// registered ImplFactory for that selector's chain family.
func NewCCIP17ForChainSelector(ctx context.Context, lggr zerolog.Logger, env *deployment.Environment, chainSelector uint64) (cciptestinterfaces.CCIP17, error) {
	family, err := chain_selectors.GetSelectorFamily(chainSelector)
	if err != nil {
		return nil, fmt.Errorf("get family for selector %d: %w", chainSelector, err)
	}
	fac, err := GetImplFactory(family)
	if err != nil {
		return nil, fmt.Errorf("get impl factory for family %s: %w", family, err)
	}
	return fac.New(ctx, lggr, env, chainSelector)
}
