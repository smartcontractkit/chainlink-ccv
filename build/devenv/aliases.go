// Package ccv re-exports symbols from devutil and components/monolith so that
// existing callers don't need import changes.
//
// TODO: remove these aliases once the phased environment is the default and
// the legacy monolithic NewEnvironment path is deleted.
package ccv

import (
	"context"

	"github.com/rs/zerolog"

	cciptestinterfaces "github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	monolith "github.com/smartcontractkit/chainlink-ccv/build/devenv/components/monolith"
	devutil "github.com/smartcontractkit/chainlink-ccv/build/devenv/devutil"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	cldf_evm_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider"
)

// Type aliases — identical to the originals; methods are inherited.
type (
	Cfg                   = monolith.Cfg
	ProtocolContractsCfg  = monolith.ProtocolContractsCfg
	CLDF                  = monolith.CLDF
	CLDFEnvironmentConfig = monolith.CLDFEnvironmentConfig
	PhasedSetup           = monolith.PhasedSetup
	TimeTracker           = monolith.TimeTracker
	AggregatorClient      = monolith.AggregatorClient
)

var (
	Plog = monolith.Plog
	L    = devutil.L
)

const (
	EnvVarTestConfigs = devutil.EnvVarTestConfigs
	DefaultConfigDir  = devutil.DefaultConfigDir
)

func Load[T any](paths []string) (*T, error) { return devutil.Load[T](paths) }

func NewTimeTracker(l zerolog.Logger) *TimeTracker { return monolith.NewTimeTracker(l) }

func NewCLDFOperationsEnvironment(bc []*blockchain.Input, dataStore datastore.DataStore) ([]uint64, *deployment.Environment, error) {
	return monolith.NewCLDFOperationsEnvironment(bc, dataStore)
}

func NewCLDFOperationsEnvironmentWithOffchain(cfg CLDFEnvironmentConfig) ([]uint64, *deployment.Environment, error) {
	return monolith.NewCLDFOperationsEnvironmentWithOffchain(cfg)
}

func NewDefaultCLDFBundle(e *deployment.Environment) operations.Bundle {
	return monolith.NewDefaultCLDFBundle(e)
}

func GenerateUserTransactors(privateKeys []string) []cldf_evm_provider.SignerGenerator {
	return monolith.GenerateUserTransactors(privateKeys)
}

func NewAggregatorClient(logger zerolog.Logger, addr, caCertFile string) (*AggregatorClient, error) {
	return monolith.NewAggregatorClient(logger, addr, caCertFile)
}

func BuildEnvironmentTopology(in *Cfg, e *deployment.Environment) *ccvdeployment.EnvironmentTopology {
	return monolith.BuildEnvironmentTopology(in, e)
}

func NewProductConfigurationFromNetwork(networkType string) (cciptestinterfaces.CCIP17Configuration, error) {
	return monolith.NewProductConfigurationFromNetwork(networkType)
}

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

func PrintCLDFAddresses(in *Cfg) error { return monolith.PrintCLDFAddresses(in) }
