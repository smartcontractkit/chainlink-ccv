package jobs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

type syncProposalClient struct {
	offchain.Client
}

func (syncProposalClient) ListNodes(context.Context, *nodev1.ListNodesRequest, ...grpc.CallOption) (*nodev1.ListNodesResponse, error) {
	return &nodev1.ListNodesResponse{
		Nodes:      []*nodev1.Node{{Id: "node-1", Name: "nop-1", PublicKey: "key"}},
		TotalCount: 1,
	}, nil
}

func (syncProposalClient) ListProposals(context.Context, *jobv1.ListProposalsRequest, ...grpc.CallOption) (*jobv1.ListProposalsResponse, error) {
	return &jobv1.ListProposalsResponse{Proposals: []*jobv1.Proposal{{
		Id:       "proposal-1",
		JobId:    "jd-job-1",
		Revision: 1,
		Status:   jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED,
		Spec:     "spec",
	}}}, nil
}

func TestSyncAndVerifyJobProposalsUpdatesEnvironmentDataStore(t *testing.T) {
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ccvdeployment.SaveJob(ds, ccvshared.JobInfo{
		JobID:    "job-1",
		JDJobID:  "jd-job-1",
		NOPAlias: "nop-1",
		NodeID:   "node-1",
		Mode:     ccvshared.NOPModeCL,
		Spec:     "spec",
		Proposals: map[string]ccvshared.ProposalRevision{
			"proposal-1": {ProposalID: "proposal-1", Revision: 1, Status: ccvshared.JobProposalStatusPending},
		},
	}))
	lggr := logger.Test(t)
	env := deployment.Environment{
		Name:      "test",
		Logger:    lggr,
		DataStore: ds.Seal(),
		Offchain:  syncProposalClient{},
		NodeIDs:   []string{"node-1"},
		OperationsBundle: operations.NewBundle(
			func() context.Context { return t.Context() },
			lggr,
			operations.NewMemoryReporter(),
		),
	}

	require.NoError(t, SyncAndVerifyJobProposals(&env))

	job, err := ccvdeployment.GetJob(env.DataStore, "nop-1", "job-1")
	require.NoError(t, err)
	require.Equal(t, ccvshared.JobProposalStatusApproved, job.LatestStatus())
	require.Equal(t, "proposal-1", job.ActiveProposalID)

	originalJob, err := ccvdeployment.GetJob(ds.Seal(), "nop-1", "job-1")
	require.NoError(t, err)
	require.Equal(t, ccvshared.JobProposalStatusPending, originalJob.LatestStatus())
}
