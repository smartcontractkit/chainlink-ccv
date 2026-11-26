package changesets

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-ccip/deployment/deploy"
	ccipcommon "github.com/smartcontractkit/chainlink-ccip/deployment/utils"
	ccipchangesets "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	mcmsutil "github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

const (
	handoverRouterAddr   = "0x00000000000000000000000000000000000A0001"
	handoverRMNAddr      = "0x00000000000000000000000000000000000A0002"
	handoverDeferredAddr = "0x00000000000000000000000000000000000A0003"
	handoverTransferAddr = "0x00000000000000000000000000000000000A0004"
)

// outputProtocolContractsDeployAdapter returns a fixed deploy output, standing in
// for a family adapter that leaves the ownership handover to the changeset.
type outputProtocolContractsDeployAdapter struct {
	out adapters.ProtocolContractsDeployOutput
}

func (a *outputProtocolContractsDeployAdapter) DeployProtocolContracts() *operations.Sequence[adapters.ProtocolContractsDeployInput, adapters.ProtocolContractsDeployOutput, cldf_chain.BlockChains] {
	return operations.NewSequence(
		"stub-deploy-protocol-contracts-with-output",
		semver.MustParse("1.0.0"),
		"stub sequence returning a fixed deploy output",
		func(_ operations.Bundle, _ cldf_chain.BlockChains, _ adapters.ProtocolContractsDeployInput) (adapters.ProtocolContractsDeployOutput, error) {
			return a.out, nil
		},
	)
}

// transferCall records one ownership handover the changeset asked for.
type transferCall struct {
	qualifier string
	refs      []datastore.AddressRef
}

// stubTransferToTimelock replaces the real handover for the test and records each call.
func stubTransferToTimelock(t *testing.T, err error) *[]transferCall {
	t.Helper()
	calls := &[]transferCall{}
	prev := transferToTimelock
	transferToTimelock = func(sel uint64, _ deployment.Environment, in mcmsutil.Input, refs []datastore.AddressRef, _ *ccipchangesets.MCMSReaderRegistry, _ *deploy.TransferOwnershipAdapterRegistry) ([]mcmstypes.BatchOperation, []operations.Report[any, any], error) {
		*calls = append(*calls, transferCall{qualifier: in.Qualifier, refs: refs})
		if err != nil {
			return nil, nil, err
		}
		return handoverBatchOps(sel, handoverTransferAddr), nil, nil
	}
	t.Cleanup(func() { transferToTimelock = prev })
	return calls
}

func handoverBatchOps(sel uint64, to string) []mcmstypes.BatchOperation {
	return []mcmstypes.BatchOperation{{
		ChainSelector: mcmstypes.ChainSelector(sel),
		Transactions: []mcmstypes.Transaction{{
			To:               to,
			Data:             []byte{0x01},
			AdditionalFields: json.RawMessage(`{"value": 0}`),
		}},
	}}
}

// registerOutputAdapter makes the protocol deploy registry return out, and the
// MCMS reader resolve stub timelock and MCM addresses.
func registerOutputAdapter(t *testing.T, out adapters.ProtocolContractsDeployOutput) {
	t.Helper()
	registerProtocolContractsDeployAdapter()
	adapters.GetProtocolContractsDeployRegistry().Register(chainsel.FamilyEVM, &outputProtocolContractsDeployAdapter{out: out})
	t.Cleanup(registerProtocolContractsDeployAdapter)
}

// missingTimelockMCMSReader behaves like the EVM and Solana readers in an
// environment without MCMS: an empty ref and no error.
type missingTimelockMCMSReader struct{ stubMCMSReader }

func (missingTimelockMCMSReader) GetTimelockRef(_ deployment.Environment, _ uint64, _ mcmsutil.Input) (datastore.AddressRef, error) {
	return datastore.AddressRef{}, nil
}

func handoverDeployOutput(sel uint64) adapters.ProtocolContractsDeployOutput {
	router := datastore.AddressRef{ChainSelector: sel, Type: "Router", Version: semver.MustParse("2.0.0"), Address: handoverRouterAddr}
	rmn := datastore.AddressRef{ChainSelector: sel, Type: "RMNRemote", Version: semver.MustParse("2.0.0"), Address: handoverRMNAddr}
	return adapters.ProtocolContractsDeployOutput{
		Addresses:                  []datastore.AddressRef{router, rmn},
		BatchOps:                   handoverBatchOps(sel, handoverDeferredAddr),
		RefsToTransferOwnership:    []datastore.AddressRef{router},
		RefsToTransferOwnershipRMN: []datastore.AddressRef{rmn},
	}
}

func timelockOwnedDeployInput(sel uint64) DeployProtocolContractsInput {
	input := validProtocolDeployInput([]uint64{sel})
	input.DefaultCfg.DeployerKeyOwned = false
	input.MCMS = &mcmsutil.Input{Description: "deploy protocol contracts", TimelockAction: mcmstypes.TimelockActionSchedule}
	return input
}

func proposalTargets(t *testing.T, out deployment.ChangesetOutput) []string {
	t.Helper()
	require.Len(t, out.MCMSTimelockProposals, 1)
	var targets []string
	for _, op := range out.MCMSTimelockProposals[0].Operations {
		for _, tx := range op.Transactions {
			targets = append(targets, tx.To)
		}
	}
	return targets
}

func TestDeployProtocolContracts_Validation_TimelockOwnedRequiresMCMS(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerProtocolContractsDeployAdapter()
	input := timelockOwnedDeployInput(sel)
	input.MCMS = nil
	err := DeployProtocolContracts().VerifyPreconditions(newProtocolDeployTestEnv([]uint64{sel}), input)
	require.ErrorContains(t, err, "MCMS input is required")
}

func TestDeployProtocolContracts_Validation_DeployerKeyOwnedNeedsNoMCMS(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerProtocolContractsDeployAdapter()
	input := validProtocolDeployInput([]uint64{sel})
	input.DefaultCfg.DeployerKeyOwned = true
	input.MCMS = nil
	require.NoError(t, DeployProtocolContracts().VerifyPreconditions(newProtocolDeployTestEnv([]uint64{sel}), input))
}

func TestDeployProtocolContracts_Validation_PerChainTimelockOwnedRequiresMCMS(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerProtocolContractsDeployAdapter()
	input := validProtocolDeployInput([]uint64{sel})
	input.DefaultCfg.DeployerKeyOwned = true
	input.MCMS = nil
	input.ChainCfgs = map[uint64]DeployProtocolContractsPerChainCfg{
		sel: {DeployerContract: "0x0000000000000000000000000000000000000FAC"},
	}
	err := DeployProtocolContracts().VerifyPreconditions(newProtocolDeployTestEnv([]uint64{sel}), input)
	require.ErrorContains(t, err, "MCMS input is required")
}

func TestDeployProtocolContracts_Validation_MissingTimelock(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerProtocolContractsDeployAdapter()
	readers := ccipchangesets.NewMCMSReaderRegistry()
	readers.RegisterMCMSReader(chainsel.FamilyEVM, missingTimelockMCMSReader{})
	prev := mcmsReaders
	mcmsReaders = func() *ccipchangesets.MCMSReaderRegistry { return readers }
	t.Cleanup(func() { mcmsReaders = prev })

	err := DeployProtocolContracts().VerifyPreconditions(newProtocolDeployTestEnv([]uint64{sel}), timelockOwnedDeployInput(sel))
	require.ErrorContains(t, err, `no timelock for MCMS qualifier "CLLCCIP"`)
	require.ErrorContains(t, err, "mcms.qualifier")
}

func TestDeployProtocolContracts_Validation_InvalidMCMSInput(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerProtocolContractsDeployAdapter()
	input := timelockOwnedDeployInput(sel)
	input.MCMS.TimelockAction = "unknown"
	err := DeployProtocolContracts().VerifyPreconditions(newProtocolDeployTestEnv([]uint64{sel}), input)
	require.ErrorContains(t, err, "invalid timelock action")
}

func TestDeployProtocolContracts_Apply_TransfersOwnershipToTimelocks(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerOutputAdapter(t, handoverDeployOutput(sel))
	calls := stubTransferToTimelock(t, nil)

	out, err := DeployProtocolContracts().Apply(newTestEnvForApply(t, "nop", []uint64{sel}), timelockOwnedDeployInput(sel))
	require.NoError(t, err)

	require.Len(t, *calls, 2)
	require.Empty(t, (*calls)[0].qualifier, "product contracts go to the timelock named by the MCMS input")
	require.Equal(t, handoverRouterAddr, (*calls)[0].refs[0].Address)
	require.Equal(t, ccipcommon.RMNTimelockQualifier, (*calls)[1].qualifier)
	require.Equal(t, handoverRMNAddr, (*calls)[1].refs[0].Address)

	require.Equal(t,
		[]string{handoverTransferAddr, handoverTransferAddr, handoverDeferredAddr},
		proposalTargets(t, out),
		"the timelock accepts ownership before the deferred write, and nothing else is proposed")

	refs, err := out.DataStore.Addresses().Fetch()
	require.NoError(t, err)
	require.Len(t, refs, 2)
}

func TestDeployProtocolContracts_Apply_DeployerKeyOwnedSkipsHandover(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	deployOut := handoverDeployOutput(sel)
	deployOut.BatchOps = nil
	registerOutputAdapter(t, deployOut)
	calls := stubTransferToTimelock(t, nil)

	input := validProtocolDeployInput([]uint64{sel})
	input.DefaultCfg.DeployerKeyOwned = true
	input.MCMS = nil
	out, err := DeployProtocolContracts().Apply(newTestEnvForApply(t, "nop", []uint64{sel}), input)
	require.NoError(t, err)
	require.Empty(t, *calls)
	require.Empty(t, out.MCMSTimelockProposals)
}

func TestDeployProtocolContracts_Apply_HandoverFailureKeepsDeployedRefs(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerOutputAdapter(t, handoverDeployOutput(sel))
	stubTransferToTimelock(t, errors.New("timelock not found"))

	out, err := DeployProtocolContracts().Apply(newTestEnvForApply(t, "nop", []uint64{sel}), timelockOwnedDeployInput(sel))
	require.ErrorContains(t, err, "failed to transfer ownership to timelock")
	require.ErrorContains(t, err, "timelock not found")

	refs, err := out.DataStore.Addresses().Fetch()
	require.NoError(t, err)
	require.Len(t, refs, 2, "a retry must find the deployed contracts instead of redeploying them")
}

// TestDeployProtocolContracts_Apply_RunTwiceProposesNothing models the second run after the
// proposal executed: the adapter finds every contract and returns no refs to hand over.
func TestDeployProtocolContracts_Apply_RunTwiceProposesNothing(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	deployOut := handoverDeployOutput(sel)
	deployOut.BatchOps = nil
	deployOut.RefsToTransferOwnership = nil
	deployOut.RefsToTransferOwnershipRMN = nil
	registerOutputAdapter(t, deployOut)
	calls := stubTransferToTimelock(t, nil)

	out, err := DeployProtocolContracts().Apply(newTestEnvForApply(t, "nop", []uint64{sel}), timelockOwnedDeployInput(sel))
	require.NoError(t, err)
	require.Empty(t, *calls)
	require.Empty(t, out.MCMSTimelockProposals)
}

func TestDeployProtocolContracts_Validation_RejectsNonCLLQualifier(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerProtocolContractsDeployAdapter()
	input := timelockOwnedDeployInput(sel)
	input.MCMS.Qualifier = "ccvOwner"
	err := DeployProtocolContracts().VerifyPreconditions(newProtocolDeployTestEnv([]uint64{sel}), input)
	require.ErrorContains(t, err, `got MCMS qualifier "ccvOwner"`)
}
