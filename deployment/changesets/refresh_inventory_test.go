package changesets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/inventory"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

const (
	refreshEthereumSelector = uint64(5009297550715157269)
	refreshCantonSelector   = uint64(2308837218439511688)
	refreshSigner           = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
)

type refreshInventoryOnchainAdapter struct {
	adapters.CommitteeVerifierOnchainAdapter
}

func (refreshInventoryOnchainAdapter) ScanCommitteeStates(
	_ context.Context,
	_ deployment.Environment,
	chain uint64,
) ([]*adapters.CommitteeState, error) {
	return []*adapters.CommitteeState{{
		Qualifier: "default", ChainSelector: chain, Address: "canton-cv",
		SignatureConfigs: []adapters.SignatureConfig{{
			SourceChainSelector: refreshEthereumSelector, Threshold: 1, Signers: []string{refreshSigner},
		}},
	}}, nil
}

func TestRefreshInventorySyncsJDAndPersistsOnchainCommittees(t *testing.T) {
	adapters.GetCommitteeVerifierOnchainRegistry().Register("canton", refreshInventoryOnchainAdapter{})
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ccvdeployment.SaveNOPSigners(ds, map[string]map[string]string{"nop-a": {"evm": refreshSigner}}))
	require.NoError(t, ccvdeployment.SaveJDNodes(ds, map[string]ccvdeployment.JDNode{
		"node-a": {Name: "nop-a", CSAKey: "csa-old"},
	}))
	require.NoError(t, ccvdeployment.SaveAggregatorConfig(ds, "aggregator-1", &model.Committee{
		QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{
			"5009297550715157269": {Signers: []model.Signer{{Address: refreshSigner}}, Threshold: 1},
		},
		DestinationVerifiers: map[model.DestinationSelector]string{"2308837218439511688": "canton-cv"},
	}))
	require.NoError(t, ccvdeployment.SaveAggregatorQualifier(ds, "aggregator-1", "default"))

	verifierSpec := "type = \"ccvcommitteeverifier\"\n"
	for _, job := range []shared.JobInfo{
		{JobID: "job-accepted", JDJobID: "jd-accepted", NOPAlias: "nop-a", NodeID: "node-a", Spec: verifierSpec},
		{JobID: "job-rejected", JDJobID: "jd-rejected", NOPAlias: "nop-a", NodeID: "node-a", Spec: verifierSpec},
	} {
		job.Proposals = map[string]shared.ProposalRevision{
			"stale": {ProposalID: "stale", Revision: 1, Status: shared.JobProposalStatusPending},
		}
		require.NoError(t, ccvdeployment.SaveJob(ds, job))
	}
	client := &stubOffchainClient{
		nodes: map[string]string{"node-a": "nop-a"},
		proposals: map[string][]*jobv1.Proposal{
			"jd-accepted": {{Id: "p-accepted", JobId: "jd-accepted", Revision: 2, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: verifierSpec}},
			"jd-rejected": {{Id: "p-rejected", JobId: "jd-rejected", Revision: 2, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_REJECTED, Spec: verifierSpec}},
		},
	}
	err := RefreshInventory().VerifyPreconditions(deployment.Environment{DataStore: ds.Seal()}, RefreshInventoryInput{})
	require.ErrorContains(t, err, "JD")

	lggr := logger.Test(t)
	out, err := RefreshInventory().Apply(deployment.Environment{
		Name: "test", Logger: lggr, DataStore: ds.Seal(), GetContext: t.Context,
		Offchain: client, NodeIDs: []string{"node-a"},
		OperationsBundle: operations.NewBundle(t.Context, lggr, operations.NewMemoryReporter()),
	}, RefreshInventoryInput{})
	require.NoError(t, err)
	require.NotNil(t, out.DataStore)
	assertOnchainMember(t, out.DataStore.Seal(), "csa-node-a")

	inv, err := ccvdeployment.GetInventory(out.DataStore.Seal())
	require.NoError(t, err)
	require.Len(t, inv.Nodes, 1)
	scopes := make(map[string]inventory.VerifierScope, len(inv.Nodes[0].VerifierScopes))
	for _, scope := range inv.Nodes[0].VerifierScopes {
		scopes[scope.JobID] = scope
	}
	assert.Equal(t, "approved", scopes["job-accepted"].LatestProposalStatus)
	assert.True(t, scopes["job-accepted"].HasActiveProposal)
	assert.Equal(t, "p-accepted", scopes["job-accepted"].ActiveProposalID)
	assert.Equal(t, "rejected", scopes["job-rejected"].LatestProposalStatus)
	assert.False(t, scopes["job-rejected"].HasActiveProposal)
	assert.Len(t, client.proposalRequests, 2)

	require.NoError(t, ccvdeployment.SaveJDNodes(out.DataStore, map[string]ccvdeployment.JDNode{
		"node-a": {Name: "nop-a", CSAKey: "csa-new"},
	}))
	assertOnchainMember(t, out.DataStore.Seal(), "csa-new")
}

func assertOnchainMember(t *testing.T, ds datastore.DataStore, csaKey string) {
	t.Helper()
	inv, err := ccvdeployment.GetInventory(ds)
	require.NoError(t, err)
	var onchain []inventory.Committee
	for _, c := range inv.Committees {
		if c.Source == inventory.SourceOnchain {
			onchain = append(onchain, c)
		}
	}
	require.Len(t, onchain, 1)
	require.Len(t, onchain[0].VerifierDeployments, 1)
	assert.Equal(t, inventory.ChainSelector(refreshCantonSelector), onchain[0].VerifierDeployments[0].Chain)
	require.Len(t, onchain[0].Members, 1)
	assert.Equal(t, inventory.Member{
		SignerAddress: refreshSigner, NOPAlias: "nop-a", NodeID: "node-a", CSAKey: csaKey,
	}, onchain[0].Members[0])

	require.Len(t, inv.Refreshes, 1, "the refresh outcome survives later CCV metadata writes")
	assert.Equal(t, inventory.ChainSelector(refreshCantonSelector), inv.Refreshes[0].Chain)
	assert.False(t, inv.Refreshes[0].LastSuccessAt.IsZero())
	assert.Empty(t, inv.Refreshes[0].LastError)
}
