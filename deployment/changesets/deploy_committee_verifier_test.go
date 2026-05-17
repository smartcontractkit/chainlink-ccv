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

// stubDeployAdapter implements adapters.CommitteeVerifierDeployAdapter for
// validation tests. The sequence body is never executed in the validation
// path so the inner func just panics if reached unexpectedly.
type stubDeployAdapter struct{}

var _ adapters.CommitteeVerifierDeployAdapter = (*stubDeployAdapter)(nil)

var stubDeploySequence = operations.NewSequence(
	"stub-deploy-committee-verifier",
	semver.MustParse("1.0.0"),
	"stub sequence used only by validation tests",
	func(_ operations.Bundle, _ cldf_chain.BlockChains, _ adapters.DeployCommitteeVerifierInput) (adapters.DeployCommitteeVerifierOutput, error) {
		return adapters.DeployCommitteeVerifierOutput{}, nil
	},
)

func (s *stubDeployAdapter) DeployCommitteeVerifier() *operations.Sequence[adapters.DeployCommitteeVerifierInput, adapters.DeployCommitteeVerifierOutput, cldf_chain.BlockChains] {
	return stubDeploySequence
}

// newDeployTestRegistry registers the stub deploy adapter for the EVM family
// in the singleton registry. Other test files may already have registered
// fields for the same family; Register only overwrites non-nil fields, so
// adding CommitteeVerifierDeploy here does not disturb them.
func newDeployTestRegistry() *adapters.Registry {
	r := adapters.GetRegistry()
	r.Register(chainsel.FamilyEVM, adapters.ChainAdapters{
		CommitteeVerifierDeploy: &stubDeployAdapter{},
	})
	return r
}

func newDeployTestEnv(selectors []uint64) deployment.Environment {
	return deployment.Environment{
		BlockChains: newTestBlockChains(selectors),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}
}

func validCommittee() adapters.CommitteeVerifierDeployParams {
	return adapters.CommitteeVerifierDeployParams{
		Version:       semver.MustParse("2.0.0"),
		FeeAggregator: "0x000000000000000000000000000000000000FEED",
		Qualifier:     "default",
	}
}

func validInput(selectors []uint64) DeployCommitteeVerifierInput {
	return DeployCommitteeVerifierInput{
		ChainSelectors: selectors,
		Committees:     []adapters.CommitteeVerifierDeployParams{validCommittee()},
		DefaultCfg: DeployCommitteeVerifierPerChainCfg{
			DeployerContract: "0x0000000000000000000000000000000000000FAC",
		},
	}
}

func TestDeployCommitteeVerifier_Validation_NoChainSelectors(t *testing.T) {
	cs := DeployCommitteeVerifier(newDeployTestRegistry())
	err := cs.VerifyPreconditions(newDeployTestEnv(nil), DeployCommitteeVerifierInput{
		Committees: []adapters.CommitteeVerifierDeployParams{validCommittee()},
	})
	require.ErrorContains(t, err, "at least one chain selector is required")
}

func TestDeployCommitteeVerifier_Validation_NoCommittees(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cs := DeployCommitteeVerifier(newDeployTestRegistry())
	err := cs.VerifyPreconditions(newDeployTestEnv([]uint64{sel}), DeployCommitteeVerifierInput{
		ChainSelectors: []uint64{sel},
		DefaultCfg: DeployCommitteeVerifierPerChainCfg{
			DeployerContract: "0x0000000000000000000000000000000000000FAC",
		},
	})
	require.ErrorContains(t, err, "at least one committee is required")
}

func TestDeployCommitteeVerifier_Validation_DuplicateChainSelectors(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cs := DeployCommitteeVerifier(newDeployTestRegistry())
	err := cs.VerifyPreconditions(newDeployTestEnv([]uint64{sel}), validInput([]uint64{sel, sel}))
	require.ErrorContains(t, err, "duplicate chain selector")
}

func TestDeployCommitteeVerifier_Validation_ChainNotInEnvironment(t *testing.T) {
	envSel := chainsel.TEST_90000001.Selector
	otherSel := chainsel.TEST_90000002.Selector
	cs := DeployCommitteeVerifier(newDeployTestRegistry())
	err := cs.VerifyPreconditions(newDeployTestEnv([]uint64{envSel}), validInput([]uint64{otherSel}))
	require.ErrorContains(t, err, "is not available in environment")
}

func TestDeployCommitteeVerifier_Validation_MissingDeployerContract(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cs := DeployCommitteeVerifier(newDeployTestRegistry())
	input := validInput([]uint64{sel})
	input.DefaultCfg.DeployerContract = ""
	err := cs.VerifyPreconditions(newDeployTestEnv([]uint64{sel}), input)
	require.ErrorContains(t, err, "DeployerContract is required")
}

func TestDeployCommitteeVerifier_Validation_DeployerContractFromPerChainOverride(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cs := DeployCommitteeVerifier(newDeployTestRegistry())
	input := validInput([]uint64{sel})
	// Default is empty — would normally fail — but per-chain override supplies the value.
	input.DefaultCfg.DeployerContract = ""
	input.ChainCfgs = map[uint64]DeployCommitteeVerifierPerChainCfg{
		sel: {DeployerContract: "0x0000000000000000000000000000000000000FAC"},
	}
	require.NoError(t, cs.VerifyPreconditions(newDeployTestEnv([]uint64{sel}), input))
}

func TestDeployCommitteeVerifier_Validation_ChainCfgsSelectorNotInChainSelectors(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	otherSel := chainsel.TEST_90000002.Selector
	cs := DeployCommitteeVerifier(newDeployTestRegistry())
	input := validInput([]uint64{sel})
	input.ChainCfgs = map[uint64]DeployCommitteeVerifierPerChainCfg{
		otherSel: {DeployerContract: "0x0000000000000000000000000000000000000FAC"},
	}
	err := cs.VerifyPreconditions(newDeployTestEnv([]uint64{sel, otherSel}), input)
	require.ErrorContains(t, err, "ChainCfgs contains selector")
}

func TestDeployCommitteeVerifier_Validation_MissingCommitteeQualifier(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cs := DeployCommitteeVerifier(newDeployTestRegistry())
	input := validInput([]uint64{sel})
	input.Committees[0].Qualifier = ""
	err := cs.VerifyPreconditions(newDeployTestEnv([]uint64{sel}), input)
	require.ErrorContains(t, err, "committee qualifier is required")
}

func TestDeployCommitteeVerifier_Validation_DuplicateCommitteeQualifier(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cs := DeployCommitteeVerifier(newDeployTestRegistry())
	input := validInput([]uint64{sel})
	input.Committees = append(input.Committees, validCommittee())
	err := cs.VerifyPreconditions(newDeployTestEnv([]uint64{sel}), input)
	require.ErrorContains(t, err, "duplicate committee qualifier")
}

func TestDeployCommitteeVerifier_Validation_MissingCommitteeVersion(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cs := DeployCommitteeVerifier(newDeployTestRegistry())
	input := validInput([]uint64{sel})
	input.Committees[0].Version = nil
	err := cs.VerifyPreconditions(newDeployTestEnv([]uint64{sel}), input)
	require.ErrorContains(t, err, "Version is required")
}

func TestDeployCommitteeVerifier_Validation_MissingFeeAggregator(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cs := DeployCommitteeVerifier(newDeployTestRegistry())
	input := validInput([]uint64{sel})
	input.Committees[0].FeeAggregator = ""
	err := cs.VerifyPreconditions(newDeployTestEnv([]uint64{sel}), input)
	require.ErrorContains(t, err, "FeeAggregator is required")
}

func TestDeployCommitteeVerifier_Validation_HappyPath(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cs := DeployCommitteeVerifier(newDeployTestRegistry())
	require.NoError(t, cs.VerifyPreconditions(newDeployTestEnv([]uint64{sel}), validInput([]uint64{sel})))
}
