// Package monolith re-exports utilities from devutil so that protocol_contracts
// (and other components) only need a single import alias.
package monolith

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	devutil "github.com/smartcontractkit/chainlink-ccv/build/devenv/devutil"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

var L = devutil.L

const (
	EnvVarTestConfigs = devutil.EnvVarTestConfigs
	DefaultConfigDir  = devutil.DefaultConfigDir
)

func Load[T any](paths []string) (*T, error) { return devutil.Load[T](paths) }

func DeployContractsForSelector(
	ctx context.Context,
	env *deployment.Environment,
	impl cciptestinterfaces.OnChainConfigurable,
	selector uint64,
	topology *ccvdeployment.EnvironmentTopology,
) (datastore.DataStore, error) {
	return devutil.DeployContractsForSelector(ctx, env, impl, selector, topology)
}

func ConnectAllChainsCanonical(
	impls []cciptestinterfaces.CCIP17Configuration,
	blockchains []*blockchain.Input,
	selectors []uint64,
	e *deployment.Environment,
	topology *ccvdeployment.EnvironmentTopology,
) error {
	return devutil.ConnectAllChainsCanonical(impls, blockchains, selectors, e, topology)
}

func ConnectAllChainsLegacy(
	impls []cciptestinterfaces.CCIP17Configuration,
	blockchains []*blockchain.Input,
	selectors []uint64,
	e *deployment.Environment,
	topology *ccvdeployment.EnvironmentTopology,
) error {
	return devutil.ConnectAllChainsLegacy(impls, blockchains, selectors, e, topology)
}

func DeployTokensAndPools(
	impl cciptestinterfaces.TokenConfigProvider,
	env *deployment.Environment,
	selector uint64,
	combos []devenvcommon.TokenCombination,
	deltaDS *datastore.MemoryDataStore,
) error {
	return devutil.DeployTokensAndPools(impl, env, selector, combos, deltaDS)
}

func ConfigureAllTokenTransfers(
	impls []cciptestinterfaces.CCIP17Configuration,
	selectors []uint64,
	env *deployment.Environment,
	topology *ccvdeployment.EnvironmentTopology,
) error {
	return devutil.ConfigureAllTokenTransfers(impls, selectors, env, topology)
}
