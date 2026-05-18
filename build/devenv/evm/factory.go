package evm

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// ImplFactory implements chainreg.ImplFactory for EVM chains.
type ImplFactory struct{}

func (f *ImplFactory) NewEmpty() cciptestinterfaces.CCIP17Configuration {
	return NewEmptyCCIP17EVM()
}

func (f *ImplFactory) New(
	ctx context.Context,
	lggr zerolog.Logger,
	env *deployment.Environment,
	chainSelector uint64,
) (cciptestinterfaces.CCIP17, error) {
	return NewCCIP17EVM(ctx, lggr, env, chainSelector)
}

func (f *ImplFactory) DefaultSignerKey(keys services.BootstrapKeys) string {
	return keys.ECDSAAddress
}

func (f *ImplFactory) DefaultFeeAggregator(env *deployment.Environment, chainSelector uint64) string {
	evmChains := env.BlockChains.EVMChains()
	if chain, ok := evmChains[chainSelector]; ok {
		return chain.DeployerKey.From.Hex()
	}
	return ""
}

func (f *ImplFactory) SupportsFunding() bool {
	return true
}
