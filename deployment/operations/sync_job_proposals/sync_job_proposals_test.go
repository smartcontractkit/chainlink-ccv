package sync_job_proposals

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

type driftJDClient struct {
	shared.JDClient
	proposals []*jobv1.Proposal
	requests  []*jobv1.ListProposalsRequest
}

func (c *driftJDClient) ListProposals(_ context.Context, req *jobv1.ListProposalsRequest, _ ...grpc.CallOption) (*jobv1.ListProposalsResponse, error) {
	c.requests = append(c.requests, req)
	return &jobv1.ListProposalsResponse{Proposals: c.proposals}, nil
}

func TestSyncJobProposalsDetectsDriftWithoutPersistedProposalSpecs(t *testing.T) {
	t.Parallel()

	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ccvdeployment.SaveJob(ds, shared.JobInfo{
		JobID:            "job-1",
		JDJobID:          "jd-job-1",
		NOPAlias:         "nop-1",
		NodeID:           "node-1",
		Spec:             "local-spec",
		ActiveProposalID: "p-old",
		Proposals: map[string]shared.ProposalRevision{
			"p-old": {ProposalID: "p-old", Revision: 1, Status: shared.JobProposalStatusApproved},
		},
	}))
	client := &driftJDClient{proposals: []*jobv1.Proposal{
		{Id: "p-old", JobId: "jd-job-1", Revision: 1, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: "local-spec"},
		{Id: "p-new", JobId: "jd-job-1", Revision: 2, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_PROPOSED, Spec: "remote-spec"},
	}}
	lggr := logger.Test(t)
	bundle := operations.NewBundle(
		func() context.Context { return t.Context() },
		lggr,
		operations.NewMemoryReporter(),
	)
	env := deployment.Environment{
		Logger:    lggr,
		DataStore: ds.Seal(),
		NodeIDs:   []string{"node-1"},
	}

	report, err := operations.ExecuteOperation(
		bundle,
		SyncJobProposals,
		SyncJobProposalsDeps{Env: env, JDClient: client},
		SyncJobProposalsInput{},
	)
	require.NoError(t, err)
	require.Empty(t, report.Output.Errors)
	require.Equal(t, []ProposalSpecDrift{{
		NOPAlias:  "nop-1",
		JobID:     "job-1",
		LocalSpec: "local-spec",
		JDSpec:    "remote-spec",
	}}, report.Output.SpecDrifts)
	require.Len(t, client.requests, 1)
	require.Equal(t, []string{"jd-job-1"}, client.requests[0].GetFilter().GetJobIds())

	stored, err := ccvdeployment.GetJob(report.Output.DataStore.Seal(), "nop-1", "job-1")
	require.NoError(t, err)
	require.Equal(t, "local-spec", stored.Spec)
	require.Equal(t, "p-old", stored.ActiveProposalID)
	require.Equal(t, "p-new", stored.LatestProposal().ProposalID)
	require.Empty(t, stored.LatestProposal().Spec)
}
