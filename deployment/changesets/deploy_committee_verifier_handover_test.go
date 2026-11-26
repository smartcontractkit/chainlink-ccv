package changesets

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	mcmstypes "github.com/smartcontractkit/mcms/types"

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
	require.Equal(t,
		[]string{handoverTransferAddr, handoverDeferredAddr},
		proposalTargets(t, out),
		"the timelock accepts ownership before the deferred write")
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

// Environments without MCMS keep the deployer as owner and need no MCMS input.
func TestDeployCommitteeVerifier_DeployerKeyOwnedWithoutMCMS(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	deployOut := verifierDeployOutput(sel)
	deployOut.BatchOps = nil
	deployOut.RefsToTransferOwnership = nil
	adapter := registerOutputCommitteeVerifierAdapter(t, deployOut)
	calls := stubTransferToTimelock(t, nil)

	input := validInput([]uint64{sel})
	input.DefaultCfg.DeployerKeyOwned = true
	input.MCMS = nil
	require.NoError(t, DeployCommitteeVerifier().VerifyPreconditions(newDeployTestEnv([]uint64{sel}), input))

	out, err := DeployCommitteeVerifier().Apply(newTestEnvForApply(t, "nop", []uint64{sel}), input)
	require.NoError(t, err)
	require.True(t, *adapter.deployerKeyOwned)
	require.Empty(t, *calls)
	require.Empty(t, out.MCMSTimelockProposals)
	refs, err := out.DataStore.Addresses().Fetch()
	require.NoError(t, err)
	require.Len(t, refs, 1)
}

func TestOnboardChain_DeployerKeyOwnedWithoutMCMS(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	protocolOut := handoverDeployOutput(sel)
	protocolOut.BatchOps = nil
	registerOutputAdapter(t, protocolOut)
	cvOut := verifierDeployOutput(sel)
	cvOut.BatchOps = nil
	registerOutputCommitteeVerifierAdapter(t, cvOut)
	calls := stubTransferToTimelock(t, nil)

	protocol := validProtocolDeployInput([]uint64{sel})
	protocol.DefaultCfg.DeployerKeyOwned = true
	protocol.MCMS = nil
	cv := validInput([]uint64{sel})
	cv.DefaultCfg.DeployerKeyOwned = true
	cv.MCMS = nil
	input := OnboardChainInput{ProtocolContracts: protocol, CommitteeVerifiers: cv}

	env := newTestEnvForApply(t, "nop", []uint64{sel})
	require.NoError(t, OnboardChain().VerifyPreconditions(env, input))
	out, err := OnboardChain().Apply(env, input)
	require.NoError(t, err)
	require.Empty(t, *calls, "refs returned by the adapter are ignored when the deployer keeps ownership")
	require.Empty(t, out.MCMSTimelockProposals)
}

// EVM sequences return a batch op per chain even when every write went out with the
// deployer key; it has no transactions and needs no MCMS input.
func TestDeployProtocolContracts_EmptyBatchOpsNeedNoMCMS(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	deployOut := handoverDeployOutput(sel)
	deployOut.BatchOps = []mcmstypes.BatchOperation{{ChainSelector: mcmstypes.ChainSelector(sel)}}
	registerOutputAdapter(t, deployOut)
	stubTransferToTimelock(t, nil)

	input := validProtocolDeployInput([]uint64{sel})
	input.DefaultCfg.DeployerKeyOwned = true
	input.MCMS = nil
	out, err := DeployProtocolContracts().Apply(newTestEnvForApply(t, "nop", []uint64{sel}), input)
	require.NoError(t, err)
	require.Empty(t, out.MCMSTimelockProposals)
}
