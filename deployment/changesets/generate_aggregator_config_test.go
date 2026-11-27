package changesets

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/inventory"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

const (
	genSignerA = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
	genSignerB = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf"
)

// A normal chain-aware run starting with an empty inventory publishes the observed signer set
// and quorum in env metadata on the first run, and a threshold override never rewrites them.
func TestGenerateAggregatorConfigPublishesObservedCommittees(t *testing.T) {
	selA := chainsel.TEST_90000001.Selector
	selB := chainsel.TEST_90000002.Selector
	registerFullEVMAdapters(&stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{selA: {{
			Qualifier: "default", ChainSelector: selA, Address: "0x0000000000000000000000000000000000000002",
			SignatureConfigs: []adapters.SignatureConfig{{
				SourceChainSelector: selB, Threshold: 2, Signers: []string{genSignerA, genSignerB},
			}},
		}}},
		verifierAddrs: map[uint64]string{selA: "0x0000000000000000000000000000000000000002", selB: "0x0000000000000000000000000000000000000003"},
	})
	env := newTestEnvForApply(t, "nop1", []uint64{selA, selB})
	env.GetContext = t.Context
	verifierSpec := "type = \"ccvcommitteeverifier\"\n"
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ccvdeployment.SaveJob(ds, shared.JobInfo{
		JobID: "live-verifier", JDJobID: "jd-live", NOPAlias: "nop1", NodeID: "node-nop1", Spec: verifierSpec,
		Proposals: map[string]shared.ProposalRevision{
			"stale": {ProposalID: "stale", Revision: 1, Status: shared.JobProposalStatusPending},
		},
	}))
	env.DataStore = ds.Seal()
	client := env.Offchain.(*stubOffchainClient)
	client.proposals = map[string][]*jobv1.Proposal{
		"jd-live": {{Id: "p-live", JobId: "jd-live", Revision: 2, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: verifierSpec}},
	}
	override := uint8(5)

	out, err := GenerateAggregatorConfig().Apply(env, GenerateAggregatorConfigInput{
		ServiceIdentifier:  "agg-1",
		CommitteeQualifier: "default",
		ChainSelectors:     []uint64{selA, selB},
		ThresholdOverride:  &override,
	})
	require.NoError(t, err)
	require.NotNil(t, out.DataStore)

	// The generated config carries the override; the observed committee keeps the raw quorum.
	agg, err := ccvdeployment.GetAggregatorConfig(out.DataStore.Seal(), "agg-1")
	require.NoError(t, err)
	require.Contains(t, agg.QuorumConfigs, fmt.Sprint(selB))
	assert.Equal(t, override, agg.QuorumConfigs[fmt.Sprint(selB)].Threshold)

	inv, err := ccvdeployment.GetInventory(out.DataStore.Seal())
	require.NoError(t, err)
	var onchain []inventory.Committee
	for _, c := range inv.Committees {
		if c.Source == inventory.SourceOnchain {
			onchain = append(onchain, c)
		}
	}
	require.Len(t, onchain, 1, "the first run already publishes the observed committee")
	require.Len(t, onchain[0].VerifierDeployments, 1)
	assert.Equal(t, inventory.ChainSelector(selA), onchain[0].VerifierDeployments[0].Chain)
	assert.Equal(t, inventory.ChainSelector(selB), onchain[0].SourceChain)
	assert.Equal(t, uint8(2), onchain[0].Threshold, "the inventory keeps the onchain quorum, not the override")
	require.Len(t, onchain[0].Members, 2)
	addresses := []string{onchain[0].Members[0].SignerAddress, onchain[0].Members[1].SignerAddress}
	assert.ElementsMatch(t, []string{genSignerA, genSignerB}, addresses)

	require.Len(t, inv.Refreshes, 2, "both scanned chains record a successful refresh")
	for _, refresh := range inv.Refreshes {
		assert.Empty(t, refresh.LastError)
		assert.False(t, refresh.LastSuccessAt.IsZero())
	}

	require.Len(t, inv.Nodes, 1)
	require.Len(t, inv.Nodes[0].VerifierScopes, 1)
	assert.Equal(t, "live-verifier", inv.Nodes[0].VerifierScopes[0].JobID)
	assert.Equal(t, "approved", inv.Nodes[0].VerifierScopes[0].LatestProposalStatus)
	assert.True(t, inv.Nodes[0].VerifierScopes[0].HasActiveProposal)
	assert.Len(t, client.proposalRequests, 1)
}
