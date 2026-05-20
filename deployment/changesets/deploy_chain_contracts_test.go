package changesets

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// stubChainContractsDeployAdapter implements adapters.ChainContractsDeployAdapter
// for validation tests.
type stubChainContractsDeployAdapter struct{}

var _ adapters.ChainContractsDeployAdapter = (*stubChainContractsDeployAdapter)(nil)

var stubChainContractsDeploySequence = operations.NewSequence(
	"stub-deploy-chain-contracts",
	semver.MustParse("1.0.0"),
	"stub sequence used only by validation tests",
	func(_ operations.Bundle, _ cldf_chain.BlockChains, _ adapters.ChainContractsDeployInput) (adapters.ChainContractsDeployOutput, error) {
		return adapters.ChainContractsDeployOutput{}, nil
	},
)

func (s *stubChainContractsDeployAdapter) DeployChainContracts() *operations.Sequence[adapters.ChainContractsDeployInput, adapters.ChainContractsDeployOutput, cldf_chain.BlockChains] {
	return stubChainContractsDeploySequence
}

func newChainDeployTestRegistry() *adapters.Registry {
	r := adapters.GetRegistry()
	r.Register(chainsel.FamilyEVM, adapters.ChainAdapters{
		ChainContractsDeploy: &stubChainContractsDeployAdapter{},
	})
	return r
}

func newChainDeployTestEnv(selectors []uint64) deployment.Environment {
	return deployment.Environment{
		BlockChains: newTestBlockChains(selectors),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}
}

func validDeployInput(selectors []uint64) DeployChainContractsInput {
	return DeployChainContractsInput{
		ChainSelectors: selectors,
		DefaultCfg: DeployChainContractsPerChainCfg{
			DeployerContract: "0x0000000000000000000000000000000000000FAC",
		},
	}
}

func TestDeployChainContracts_Validation_NoChainSelectors(t *testing.T) {
	cs := DeployChainContracts(newChainDeployTestRegistry())
	err := cs.VerifyPreconditions(newChainDeployTestEnv(nil), DeployChainContractsInput{
		DefaultCfg: DeployChainContractsPerChainCfg{
			DeployerContract: "0x0000000000000000000000000000000000000FAC",
		},
	})
	require.ErrorContains(t, err, "at least one chain selector is required")
}

func TestDeployChainContracts_Validation_DuplicateChainSelectors(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cs := DeployChainContracts(newChainDeployTestRegistry())
	err := cs.VerifyPreconditions(newChainDeployTestEnv([]uint64{sel}), validDeployInput([]uint64{sel, sel}))
	require.ErrorContains(t, err, "duplicate chain selector")
}

func TestDeployChainContracts_Validation_ChainNotInEnv(t *testing.T) {
	envSel := chainsel.TEST_90000001.Selector
	otherSel := chainsel.TEST_90000002.Selector
	cs := DeployChainContracts(newChainDeployTestRegistry())
	err := cs.VerifyPreconditions(newChainDeployTestEnv([]uint64{envSel}), validDeployInput([]uint64{otherSel}))
	require.ErrorContains(t, err, "is not available in environment")
}

func TestDeployChainContracts_Validation_MissingDeployerContract(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cs := DeployChainContracts(newChainDeployTestRegistry())
	input := validDeployInput([]uint64{sel})
	input.DefaultCfg.DeployerContract = ""
	err := cs.VerifyPreconditions(newChainDeployTestEnv([]uint64{sel}), input)
	require.ErrorContains(t, err, "DeployerContract is required")
}

func TestDeployChainContracts_Validation_DeployerContractFromPerChainOverride(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cs := DeployChainContracts(newChainDeployTestRegistry())
	input := validDeployInput([]uint64{sel})
	input.DefaultCfg.DeployerContract = ""
	input.ChainCfgs = map[uint64]DeployChainContractsPerChainCfg{
		sel: {DeployerContract: "0x0000000000000000000000000000000000000FAC"},
	}
	require.NoError(t, cs.VerifyPreconditions(newChainDeployTestEnv([]uint64{sel}), input))
}

func TestDeployChainContracts_Validation_ChainCfgsSelectorNotInChainSelectors(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	otherSel := chainsel.TEST_90000002.Selector
	cs := DeployChainContracts(newChainDeployTestRegistry())
	input := validDeployInput([]uint64{sel})
	input.ChainCfgs = map[uint64]DeployChainContractsPerChainCfg{
		otherSel: {DeployerContract: "0x0000000000000000000000000000000000000FAC"},
	}
	err := cs.VerifyPreconditions(newChainDeployTestEnv([]uint64{sel, otherSel}), input)
	require.ErrorContains(t, err, "ChainCfgs contains selector")
}

func TestDeployChainContracts_Validation_NoAdapter(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	r := adapters.NewRegistry()
	r.Register(chainsel.FamilyEVM, adapters.ChainAdapters{})
	cs := DeployChainContracts(r)
	err := cs.VerifyPreconditions(newChainDeployTestEnv([]uint64{sel}), validDeployInput([]uint64{sel}))
	require.ErrorContains(t, err, "no ChainContractsDeploy adapter registered")
}

func TestDeployChainContracts_Validation_HappyPath(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cs := DeployChainContracts(newChainDeployTestRegistry())
	require.NoError(t, cs.VerifyPreconditions(newChainDeployTestEnv([]uint64{sel}), validDeployInput([]uint64{sel})))
}

func TestDeployChainContracts_Validation_MultipleChains(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector
	cs := DeployChainContracts(newChainDeployTestRegistry())
	require.NoError(t, cs.VerifyPreconditions(
		newChainDeployTestEnv([]uint64{sel1, sel2}),
		validDeployInput([]uint64{sel1, sel2}),
	))
}

func TestDeployChainContracts_ResolveChainCfg_Default(t *testing.T) {
	input := DeployChainContractsInput{
		DefaultCfg: DeployChainContractsPerChainCfg{
			DeployerContract: "0xDEFAULT",
			DeployTestRouter: true,
		},
	}
	cfg := input.resolveChainCfg(1)
	require.Equal(t, "0xDEFAULT", cfg.DeployerContract)
	require.True(t, cfg.DeployTestRouter)
}

func TestDeployChainContracts_ResolveChainCfg_Override(t *testing.T) {
	input := DeployChainContractsInput{
		DefaultCfg: DeployChainContractsPerChainCfg{
			DeployerContract: "0xDEFAULT",
		},
		ChainCfgs: map[uint64]DeployChainContractsPerChainCfg{
			42: {DeployerContract: "0xOVERRIDE"},
		},
	}
	cfg := input.resolveChainCfg(42)
	require.Equal(t, "0xOVERRIDE", cfg.DeployerContract)
}
