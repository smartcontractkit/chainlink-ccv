package ccv

import (
	"context"
	"encoding/json"
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

	ccldf "github.com/smartcontractkit/chainlink-ccv/build/devenv/cldf"
	jdcomp "github.com/smartcontractkit/chainlink-ccv/build/devenv/components/jd"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

type effectExecutorJDClient struct {
	offchain.Client
}

func (effectExecutorJDClient) ListNodes(context.Context, *nodev1.ListNodesRequest, ...grpc.CallOption) (*nodev1.ListNodesResponse, error) {
	return &nodev1.ListNodesResponse{
		Nodes:      []*nodev1.Node{{Id: "node-1", Name: "nop-1", PublicKey: "key"}},
		TotalCount: 1,
	}, nil
}

func (effectExecutorJDClient) ProposeJob(context.Context, *jobv1.ProposeJobRequest, ...grpc.CallOption) (*jobv1.ProposeJobResponse, error) {
	return &jobv1.ProposeJobResponse{}, nil
}

func (effectExecutorJDClient) ListProposals(context.Context, *jobv1.ListProposalsRequest, ...grpc.CallOption) (*jobv1.ListProposalsResponse, error) {
	return &jobv1.ListProposalsResponse{Proposals: []*jobv1.Proposal{{
		Id:       "proposal-1",
		JobId:    "jd-job-1",
		Revision: 1,
		Status:   jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED,
		Spec:     "spec",
	}}}, nil
}

func TestExecuteJobProposalEffectsPropagatesSyncedDataStore(t *testing.T) {
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
	client := effectExecutorJDClient{}
	lggr := logger.Test(t)
	env := &deployment.Environment{
		Name:      "test",
		Logger:    lggr,
		DataStore: ds.Seal(),
		Offchain:  client,
		OperationsBundle: operations.NewBundle(
			func() context.Context { return t.Context() },
			lggr,
			operations.NewMemoryReporter(),
		),
	}
	cldf := &ccldf.CLDF{DataStore: env.DataStore, EnvMetadata: "stale"}
	accumulated := map[string]any{
		jdcomp.Key: &jobs.JDInfrastructure{
			OffchainClient: client,
			NodeIDMap:      map[string]string{"nop-1": "node-1"},
		},
		"_env": env,
		"cldf": cldf,
	}
	effects := []devenvruntime.JobProposalEffect{{
		NOPAlias: "nop-1",
		NodeID:   "node-1",
		JobSpec:  "spec",
	}}

	require.NoError(t, executeJobProposalEffects(t.Context(), effects, accumulated))

	require.Equal(t, env.DataStore, cldf.DataStore)
	for name, store := range map[string]datastore.DataStore{
		"shared environment": env.DataStore,
		"CLDF accumulator":   cldf.DataStore,
	} {
		job, err := ccvdeployment.GetJob(store, "nop-1", "job-1")
		require.NoError(t, err, name)
		require.Equal(t, ccvshared.JobProposalStatusApproved, job.LatestStatus(), name)
	}

	metadata, err := env.DataStore.EnvMetadata().Get()
	require.NoError(t, err)
	expectedMetadata, err := json.Marshal(metadata)
	require.NoError(t, err)
	require.JSONEq(t, string(expectedMetadata), cldf.EnvMetadata)
}
