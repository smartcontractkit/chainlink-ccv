package changesets

import (
	"testing"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	ccipchangesets "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	mcmsutil "github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

const (
	stubCommitteeVerifierAddr = "0x00000000000000000000000000000000000C0FFE"
	stubTimelockAddr          = "0x0000000000000000000000000000000000071CC0"
	stubMCMAddr               = "0x00000000000000000000000000000000000003C3"
)

// stubMCMSReader resolves fixed MCMS and timelock addresses so the OutputBuilder can build a proposal.
type stubMCMSReader struct{}

var _ ccipchangesets.MCMSReader = stubMCMSReader{}

func (stubMCMSReader) GetChainMetadata(_ deployment.Environment, _ uint64, _ mcmsutil.Input) (mcmstypes.ChainMetadata, error) {
	return mcmstypes.ChainMetadata{MCMAddress: stubMCMAddr}, nil
}

func (stubMCMSReader) GetTimelockRef(_ deployment.Environment, sel uint64, _ mcmsutil.Input) (datastore.AddressRef, error) {
	return datastore.AddressRef{ChainSelector: sel, Address: stubTimelockAddr}, nil
}

func (stubMCMSReader) GetMCMSRef(_ deployment.Environment, sel uint64, _ mcmsutil.Input) (datastore.AddressRef, error) {
	return datastore.AddressRef{ChainSelector: sel, Address: stubMCMAddr}, nil
}

// newCommitteeOnchainApplyEnv serves testNOPAlias from JD with signer 0xA3 so the NOP changesets resolve it.
func newCommitteeOnchainApplyEnv(t *testing.T, selectors []uint64) deployment.Environment {
	t.Helper()
	registerEVMChainTypeForIdentities()
	ccipchangesets.GetRegistry().RegisterMCMSReader(chainsel.FamilyEVM, stubMCMSReader{})
	return newIdentitiesEnv(t,
		map[string]string{"node-" + testNOPAlias: testNOPAlias},
		map[string]string{"node-" + testNOPAlias: "0xA3"},
		selectors,
	)
}

// registerNOPChangesetAdapters lets the NOP changesets discover dest chains and the signer family,
// while writes still go through stub.
func registerNOPChangesetAdapters(stub *stubOnchainAdapter) {
	registerFullEVMAdapters(&stubFullAdapter{states: stub.states})
	registerEVMOnchain(stub)
}

func twoSignerStates(selectors []uint64, threshold uint8) map[uint64][]*adapters.CommitteeState {
	states := make(map[uint64][]*adapters.CommitteeState, len(selectors))
	for _, sel := range selectors {
		states[sel] = []*adapters.CommitteeState{{
			Qualifier:     testQualifier,
			ChainSelector: sel,
			SignatureConfigs: []adapters.SignatureConfig{{
				SourceChainSelector: chainsel.TEST_90000003.Selector,
				Signers:             []string{"0xA1", "0xA2"},
				Threshold:           threshold,
			}},
		}}
	}
	return states
}

// committeeOnchainCases runs each committee onchain changeset against the stub adapter on selectors.
func committeeOnchainCases(selectors []uint64, mcmsInput *mcmsutil.Input) map[string]func(deployment.Environment, *stubOnchainAdapter) (deployment.ChangesetOutput, error) {
	return map[string]func(deployment.Environment, *stubOnchainAdapter) (deployment.ChangesetOutput, error){
		"SetAllowedFinalityConfig": func(e deployment.Environment, _ *stubOnchainAdapter) (deployment.ChangesetOutput, error) {
			return SetAllowedFinalityConfig().Apply(e, SetAllowedFinalityConfigInput{
				CommitteeQualifier: testQualifier, ChainSelectors: selectors, WaitForSafe: true, MCMS: mcmsInput,
			})
		},
		"UpdateSenderAllowlist": func(e deployment.Environment, _ *stubOnchainAdapter) (deployment.ChangesetOutput, error) {
			return UpdateSenderAllowlist().Apply(e, UpdateSenderAllowlistInput{
				CommitteeQualifier: testQualifier, ChainSelectors: selectors, DestChainSelector: chainsel.TEST_90000003.Selector,
				AllowlistEnabled: true, AddedSenders: []string{"0x000000000000000000000000000000000000aBcD"}, MCMS: mcmsInput,
			})
		},
		"IncreaseThreshold": func(e deployment.Environment, stub *stubOnchainAdapter) (deployment.ChangesetOutput, error) {
			stub.states = twoSignerStates(selectors, 1)
			return IncreaseThreshold().Apply(e, IncreaseThresholdInput{
				CommitteeQualifier: testQualifier, ChainSelectors: selectors, NewThreshold: 2, MCMS: mcmsInput,
			})
		},
		"DecreaseThreshold": func(e deployment.Environment, stub *stubOnchainAdapter) (deployment.ChangesetOutput, error) {
			stub.states = twoSignerStates(selectors, 2)
			return DecreaseThreshold().Apply(e, DecreaseThresholdInput{
				CommitteeQualifier: testQualifier, ChainSelectors: selectors, NewThreshold: 1, MCMS: mcmsInput,
			})
		},
		"AddNOPToCommittee": func(e deployment.Environment, stub *stubOnchainAdapter) (deployment.ChangesetOutput, error) {
			stub.states = twoSignerStates(selectors, 1)
			registerNOPChangesetAdapters(stub)
			return AddNOPToCommittee().Apply(e, AddNOPToCommitteeInput{
				CommitteeQualifier: testQualifier, SourceChainSelectors: []uint64{chainsel.TEST_90000003.Selector},
				NOPAlias: testNOPAlias, MCMS: mcmsInput,
			})
		},
		"RemoveNOPFromCommittee": func(e deployment.Environment, stub *stubOnchainAdapter) (deployment.ChangesetOutput, error) {
			stub.states = twoSignerStates(selectors, 1)
			for _, sel := range selectors {
				stub.states[sel][0].SignatureConfigs[0].Signers = []string{"0xA1", "0xA2", "0xA3"}
			}
			registerNOPChangesetAdapters(stub)
			return RemoveNOPFromCommittee().Apply(e, RemoveNOPFromCommitteeInput{
				CommitteeQualifier: testQualifier, SourceChainSelectors: []uint64{chainsel.TEST_90000003.Selector},
				NOPAlias: testNOPAlias, MCMS: mcmsInput,
			})
		},
	}
}

func TestCommitteeOnchainChangesets_MCMS_BuildsProposalFromAdapterBatchOps(t *testing.T) {
	selectors := []uint64{chainsel.TEST_90000001.Selector, chainsel.TEST_90000002.Selector}
	mcmsInput := &mcmsutil.Input{Description: "committee change", TimelockAction: mcmstypes.TimelockActionSchedule}
	for name, run := range committeeOnchainCases(selectors, mcmsInput) {
		t.Run(name, func(t *testing.T) {
			stub := &stubOnchainAdapter{timelockOwned: ownedBy(selectors)}
			registerEVMOnchain(stub)

			out, err := run(newCommitteeOnchainApplyEnv(t, selectors), stub)
			require.NoError(t, err)
			require.Len(t, out.MCMSTimelockProposals, 1)
			proposal := out.MCMSTimelockProposals[0]
			require.Equal(t, "committee change", proposal.Description)
			require.Len(t, proposal.Operations, len(selectors), "one batch op per chain")
			for _, sel := range selectors {
				require.Equal(t, stubTimelockAddr, proposal.TimelockAddresses[mcmstypes.ChainSelector(sel)])
			}
			for _, op := range proposal.Operations {
				require.Len(t, op.Transactions, 1)
				require.Equal(t, stubCommitteeVerifierAddr, op.Transactions[0].To)
			}
		})
	}
}

func TestCommitteeOnchainChangesets_DeployerKey_NoProposal(t *testing.T) {
	selectors := []uint64{chainsel.TEST_90000001.Selector}
	inputs := map[string]*mcmsutil.Input{"without MCMS": nil, "with MCMS": {Description: "unused when writes execute directly"}}
	for inputName, mcmsInput := range inputs {
		for name, run := range committeeOnchainCases(selectors, mcmsInput) {
			t.Run(inputName+"/"+name, func(t *testing.T) {
				stub := &stubOnchainAdapter{}
				registerEVMOnchain(stub)

				out, err := run(newCommitteeOnchainApplyEnv(t, selectors), stub)
				require.NoError(t, err)
				require.Empty(t, out.MCMSTimelockProposals, "writes executed with the deployer key leave nothing to propose")
			})
		}
	}
}

func TestCommitteeOnchainChangesets_NoMCMSInput_FailsWhenWritesNeedProposal(t *testing.T) {
	selectors := []uint64{chainsel.TEST_90000001.Selector}
	for name, run := range committeeOnchainCases(selectors, nil) {
		t.Run(name, func(t *testing.T) {
			stub := &stubOnchainAdapter{timelockOwned: ownedBy(selectors)}
			registerEVMOnchain(stub)

			out, err := run(newCommitteeOnchainApplyEnv(t, selectors), stub)
			require.ErrorContains(t, err, "set MCMS to build a proposal")
			require.Empty(t, out.MCMSTimelockProposals)
		})
	}
}

func TestCommitteeOnchainChangesets_NoMCMSInput_MixedOwners_WritesNothingDirectly(t *testing.T) {
	timelockChain, deployerChain := chainsel.TEST_90000001.Selector, chainsel.TEST_90000002.Selector
	selectors := []uint64{timelockChain, deployerChain}
	for name, run := range committeeOnchainCases(selectors, nil) {
		t.Run(name, func(t *testing.T) {
			stub := &stubOnchainAdapter{timelockOwned: ownedBy([]uint64{timelockChain})}
			registerEVMOnchain(stub)

			_, err := run(newCommitteeOnchainApplyEnv(t, selectors), stub)
			require.ErrorContains(t, err, "set MCMS to build a proposal")
			require.Empty(t, stub.directWrites, "the run must stop at the timelock-owned chain before writing the next one")
		})
	}
}

func ownedBy(selectors []uint64) map[uint64]bool {
	owned := make(map[uint64]bool, len(selectors))
	for _, sel := range selectors {
		owned[sel] = true
	}
	return owned
}
