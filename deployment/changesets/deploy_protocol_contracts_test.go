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

// stubProtocolContractsDeployAdapter implements adapters.ProtocolContractsDeployAdapter
// for validation tests.
type stubProtocolContractsDeployAdapter struct{}

var _ adapters.ProtocolContractsDeployAdapter = (*stubProtocolContractsDeployAdapter)(nil)

var stubProtocolContractsDeploySequence = operations.NewSequence(
	"stub-deploy-protocol-contracts",
	semver.MustParse("1.0.0"),
	"stub sequence used only by validation tests",
	func(_ operations.Bundle, _ cldf_chain.BlockChains, _ adapters.ProtocolContractsDeployInput) (adapters.ProtocolContractsDeployOutput, error) {
		return adapters.ProtocolContractsDeployOutput{}, nil
	},
)

func (s *stubProtocolContractsDeployAdapter) DeployProtocolContracts() *operations.Sequence[adapters.ProtocolContractsDeployInput, adapters.ProtocolContractsDeployOutput, cldf_chain.BlockChains] {
	return stubProtocolContractsDeploySequence
}

func registerProtocolContractsDeployAdapter() {
	adapters.GetProtocolContractsDeployRegistry().Register(chainsel.FamilyEVM, &stubProtocolContractsDeployAdapter{})
}

func newProtocolDeployTestEnv(selectors []uint64) deployment.Environment {
	return deployment.Environment{
		BlockChains: newTestBlockChains(selectors),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}
}

func validProtocolDeployInput(selectors []uint64) DeployProtocolContractsInput {
	return DeployProtocolContractsInput{
		ChainSelectors: selectors,
		DefaultCfg: DeployProtocolContractsPerChainCfg{
			DeployerContract: "0x0000000000000000000000000000000000000FAC",
		},
	}
}

func TestDeployProtocolContracts_Validation_NoChainSelectors(t *testing.T) {
	registerProtocolContractsDeployAdapter()
	cs := DeployProtocolContracts()
	err := cs.VerifyPreconditions(newProtocolDeployTestEnv(nil), DeployProtocolContractsInput{
		DefaultCfg: DeployProtocolContractsPerChainCfg{
			DeployerContract: "0x0000000000000000000000000000000000000FAC",
		},
	})
	require.ErrorContains(t, err, "at least one chain selector is required")
}

func TestDeployProtocolContracts_Validation_DuplicateChainSelectors(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerProtocolContractsDeployAdapter()
	cs := DeployProtocolContracts()
	err := cs.VerifyPreconditions(newProtocolDeployTestEnv([]uint64{sel}), validProtocolDeployInput([]uint64{sel, sel}))
	require.ErrorContains(t, err, "duplicate chain selector")
}

func TestDeployProtocolContracts_Validation_ChainNotInEnv(t *testing.T) {
	envSel := chainsel.TEST_90000001.Selector
	otherSel := chainsel.TEST_90000002.Selector
	registerProtocolContractsDeployAdapter()
	cs := DeployProtocolContracts()
	err := cs.VerifyPreconditions(newProtocolDeployTestEnv([]uint64{envSel}), validProtocolDeployInput([]uint64{otherSel}))
	require.ErrorContains(t, err, "is not available in environment")
}

func TestDeployProtocolContracts_Validation_MissingDeployerContract(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerProtocolContractsDeployAdapter()
	cs := DeployProtocolContracts()
	input := validProtocolDeployInput([]uint64{sel})
	input.DefaultCfg.DeployerContract = ""
	err := cs.VerifyPreconditions(newProtocolDeployTestEnv([]uint64{sel}), input)
	require.ErrorContains(t, err, "DeployerContract is required")
}

func TestDeployProtocolContracts_Validation_DeployerContractFromPerChainOverride(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerProtocolContractsDeployAdapter()
	cs := DeployProtocolContracts()
	input := validProtocolDeployInput([]uint64{sel})
	input.DefaultCfg.DeployerContract = ""
	input.ChainCfgs = map[uint64]DeployProtocolContractsPerChainCfg{
		sel: {DeployerContract: "0x0000000000000000000000000000000000000FAC"},
	}
	require.NoError(t, cs.VerifyPreconditions(newProtocolDeployTestEnv([]uint64{sel}), input))
}

func TestDeployProtocolContracts_Validation_ChainCfgsSelectorNotInChainSelectors(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	otherSel := chainsel.TEST_90000002.Selector
	registerProtocolContractsDeployAdapter()
	cs := DeployProtocolContracts()
	input := validProtocolDeployInput([]uint64{sel})
	input.ChainCfgs = map[uint64]DeployProtocolContractsPerChainCfg{
		otherSel: {DeployerContract: "0x0000000000000000000000000000000000000FAC"},
	}
	err := cs.VerifyPreconditions(newProtocolDeployTestEnv([]uint64{sel, otherSel}), input)
	require.ErrorContains(t, err, "ChainCfgs contains selector")
}

func TestDeployProtocolContracts_Validation_HappyPath(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerProtocolContractsDeployAdapter()
	cs := DeployProtocolContracts()
	require.NoError(t, cs.VerifyPreconditions(newProtocolDeployTestEnv([]uint64{sel}), validProtocolDeployInput([]uint64{sel})))
}

func TestDeployProtocolContracts_Validation_MultipleChains(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector
	registerProtocolContractsDeployAdapter()
	cs := DeployProtocolContracts()
	require.NoError(t, cs.VerifyPreconditions(
		newProtocolDeployTestEnv([]uint64{sel1, sel2}),
		validProtocolDeployInput([]uint64{sel1, sel2}),
	))
}

func TestDeployProtocolContracts_ResolveChainCfg_Default(t *testing.T) {
	input := DeployProtocolContractsInput{
		DefaultCfg: DeployProtocolContractsPerChainCfg{
			DeployerContract: "0xDEFAULT",
			DeployTestRouter: true,
		},
	}
	cfg := input.resolveChainCfg(1)
	require.Equal(t, "0xDEFAULT", cfg.DeployerContract)
	require.True(t, cfg.DeployTestRouter)
}

func TestDeployProtocolContracts_ResolveChainCfg_Override(t *testing.T) {
	input := DeployProtocolContractsInput{
		DefaultCfg: DeployProtocolContractsPerChainCfg{
			DeployerContract: "0xDEFAULT",
		},
		ChainCfgs: map[uint64]DeployProtocolContractsPerChainCfg{
			42: {DeployerContract: "0xOVERRIDE"},
		},
	}
	cfg := input.resolveChainCfg(42)
	require.Equal(t, "0xOVERRIDE", cfg.DeployerContract)
}
