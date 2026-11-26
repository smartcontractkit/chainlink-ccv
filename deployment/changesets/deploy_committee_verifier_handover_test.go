package changesets

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"

	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

const handoverVerifierAddr = "0x00000000000000000000000000000000000A0005"

// outputCommitteeVerifierDeployAdapter returns a fixed deploy output and records
// whether the changeset asked it to keep the deployer as owner.
type outputCommitteeVerifierDeployAdapter struct {
	out              adapters.CommitteeVerifierDeployOutput
	deployerKeyOwned *bool
}

func (a *outputCommitteeVerifierDeployAdapter) DeployCommitteeVerifier() *operations.Sequence[adapters.CommitteeVerifierDeployInput, adapters.CommitteeVerifierDeployOutput, cldf_chain.BlockChains] {
	return operations.NewSequence(
		"stub-deploy-committee-verifier-with-output",
		semver.MustParse("1.0.0"),
		"stub sequence returning a fixed deploy output",
		func(_ operations.Bundle, _ cldf_chain.BlockChains, in adapters.CommitteeVerifierDeployInput) (adapters.CommitteeVerifierDeployOutput, error) {
			owned := in.DeployerKeyOwned
			a.deployerKeyOwned = &owned
			return a.out, nil
		},
	)
}

func registerOutputCommitteeVerifierAdapter(t *testing.T, out adapters.CommitteeVerifierDeployOutput) *outputCommitteeVerifierDeployAdapter {
	t.Helper()
	registerDeployAdapter()
	adapter := &outputCommitteeVerifierDeployAdapter{out: out}
	adapters.GetCommitteeVerifierDeployRegistry().Register(chainsel.FamilyEVM, adapter)
	t.Cleanup(registerDeployAdapter)
	return adapter
}

func verifierDeployOutput(sel uint64) adapters.CommitteeVerifierDeployOutput {
	verifier := datastore.AddressRef{ChainSelector: sel, Type: "CommitteeVerifier", Version: semver.MustParse("2.0.0"), Qualifier: "default", Address: handoverVerifierAddr}
	return adapters.CommitteeVerifierDeployOutput{
		Addresses:               []datastore.AddressRef{verifier},
		BatchOps:                handoverBatchOps(sel, handoverDeferredAddr),
		RefsToTransferOwnership: []datastore.AddressRef{verifier},
	}
}

func TestDeployCommitteeVerifier_Validation_TimelockOwnedRequiresMCMS(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerDeployAdapter()
	input := validInput([]uint64{sel})
	input.MCMS = nil
	err := DeployCommitteeVerifier().VerifyPreconditions(newDeployTestEnv([]uint64{sel}), input)
	require.ErrorContains(t, err, "MCMS input is required")
}

func TestDeployCommitteeVerifier_Apply_TransfersOwnershipToTimelock(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	adapter := registerOutputCommitteeVerifierAdapter(t, verifierDeployOutput(sel))
	calls := stubTransferToTimelock(t, nil)

	out, err := DeployCommitteeVerifier().Apply(newTestEnvForApply(t, "nop", []uint64{sel}), validInput([]uint64{sel}))
	require.NoError(t, err)

	require.NotNil(t, adapter.deployerKeyOwned)
	require.False(t, *adapter.deployerKeyOwned, "the adapter is told to list contracts for the handover")
	require.Len(t, *calls, 1)
	require.Empty(t, (*calls)[0].qualifier)
	require.Equal(t, handoverVerifierAddr, (*calls)[0].refs[0].Address)
	require.ElementsMatch(t,
		[]string{handoverDeferredAddr, handoverTransferAddr},
		proposalTargets(t, out))
}

func TestDeployCommitteeVerifier_Apply_RunTwiceProposesNothing(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	deployOut := verifierDeployOutput(sel)
	deployOut.BatchOps = nil
	deployOut.RefsToTransferOwnership = nil
	registerOutputCommitteeVerifierAdapter(t, deployOut)
	calls := stubTransferToTimelock(t, nil)

	out, err := DeployCommitteeVerifier().Apply(newTestEnvForApply(t, "nop", []uint64{sel}), validInput([]uint64{sel}))
	require.NoError(t, err)
	require.Empty(t, *calls)
	require.Empty(t, out.MCMSTimelockProposals)
}

func TestDeployCommitteeVerifier_Apply_DeferredWritesWithoutMCMSFail(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	deployOut := verifierDeployOutput(sel)
	deployOut.RefsToTransferOwnership = nil
	registerOutputCommitteeVerifierAdapter(t, deployOut)
	calls := stubTransferToTimelock(t, nil)

	input := validInput([]uint64{sel})
	input.DefaultCfg.DeployerKeyOwned = true
	input.MCMS = nil
	_, err := DeployCommitteeVerifier().Apply(newTestEnvForApply(t, "nop", []uint64{sel}), input)
	require.ErrorContains(t, err, "no MCMS input is set")
	require.Empty(t, *calls)
}

func TestDeployProtocolContracts_Apply_DeferredWritesWithoutMCMSFail(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	deployOut := handoverDeployOutput(sel)
	deployOut.RefsToTransferOwnership = nil
	deployOut.RefsToTransferOwnershipRMN = nil
	registerOutputAdapter(t, deployOut)
	stubTransferToTimelock(t, nil)

	input := validProtocolDeployInput([]uint64{sel})
	input.DefaultCfg.DeployerKeyOwned = true
	input.MCMS = nil
	_, err := DeployProtocolContracts().Apply(newTestEnvForApply(t, "nop", []uint64{sel}), input)
	require.ErrorContains(t, err, "no MCMS input is set")
}

func TestOnboardChain_Validation_RejectsSeparateCommitteeVerifierMCMS(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerProtocolContractsDeployAdapter()
	registerDeployAdapter()
	err := OnboardChain().VerifyPreconditions(newDeployTestEnv([]uint64{sel}), OnboardChainInput{
		ProtocolContracts:  validProtocolDeployInput([]uint64{sel}),
		CommitteeVerifiers: validInput([]uint64{sel}),
	})
	require.ErrorContains(t, err, "set ProtocolContracts.MCMS, not CommitteeVerifiers.MCMS")
}

func TestOnboardChain_Apply_OneProposalForBothPhases(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerOutputAdapter(t, handoverDeployOutput(sel))
	registerOutputCommitteeVerifierAdapter(t, verifierDeployOutput(sel))
	calls := stubTransferToTimelock(t, nil)

	cv := validInput([]uint64{sel})
	cv.MCMS = nil
	out, err := OnboardChain().Apply(newTestEnvForApply(t, "nop", []uint64{sel}), OnboardChainInput{
		ProtocolContracts:  timelockOwnedDeployInput(sel),
		CommitteeVerifiers: cv,
	})
	require.NoError(t, err)
	require.Len(t, *calls, 3, "protocol contracts, RMN and committee verifier handovers")
	require.ElementsMatch(t,
		[]string{handoverDeferredAddr, handoverTransferAddr, handoverTransferAddr, handoverDeferredAddr, handoverTransferAddr},
		proposalTargets(t, out))
}
