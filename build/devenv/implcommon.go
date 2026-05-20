package ccv

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	ccdeploy "github.com/smartcontractkit/chainlink-ccv/build/devenv/deploy"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func DeployContractsForSelector(
	ctx context.Context,
	env *deployment.Environment,
	impl cciptestinterfaces.OnChainConfigurable,
	selector uint64,
	topology *ccvdeployment.EnvironmentTopology,
) (datastore.DataStore, error) {
	return ccdeploy.DeployContractsForSelector(ctx, env, impl, selector, topology)
}

func ConnectAllChainsCanonical(
	impls []cciptestinterfaces.CCIP17Configuration,
	blockchains []*blockchain.Input,
	selectors []uint64,
	e *deployment.Environment,
	topology *ccvdeployment.EnvironmentTopology,
) error {
	return ccdeploy.ConnectAllChainsCanonical(impls, blockchains, selectors, e, topology)
}

func ConnectAllChainsLegacy(
	impls []cciptestinterfaces.CCIP17Configuration,
	blockchains []*blockchain.Input,
	selectors []uint64,
	e *deployment.Environment,
	topology *ccvdeployment.EnvironmentTopology,
) error {
	return ccdeploy.ConnectAllChainsLegacy(impls, blockchains, selectors, e, topology)
}

func DeployTokensAndPools(
	impl cciptestinterfaces.TokenConfigProvider,
	env *deployment.Environment,
	selector uint64,
	combos []devenvcommon.TokenCombination,
	deltaDS *datastore.MemoryDataStore,
) error {
	return ccdeploy.DeployTokensAndPools(impl, env, selector, combos, deltaDS)
}

func ConfigureAllTokenTransfers(
	impls []cciptestinterfaces.CCIP17Configuration,
	selectors []uint64,
	env *deployment.Environment,
	topology *ccvdeployment.EnvironmentTopology,
) error {
	return ccdeploy.ConfigureAllTokenTransfers(impls, selectors, env, topology)
}
