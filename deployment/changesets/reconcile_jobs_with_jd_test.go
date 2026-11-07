package changesets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	foffchain "github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	"github.com/smartcontractkit/chainlink-deployments-framework/pkg/logger"
)

type reconcileJDClient struct {
	foffchain.Client
	jobs              []*jobv1.Job
	proposals         []*jobv1.Proposal
	listJobsRequests  []*jobv1.ListJobsRequest
	listProposalCalls []*jobv1.ListProposalsRequest
}

func (f *reconcileJDClient) ListJobs(_ context.Context, req *jobv1.ListJobsRequest, _ ...grpc.CallOption) (*jobv1.ListJobsResponse, error) {
	f.listJobsRequests = append(f.listJobsRequests, req)
	allowed := make(map[string]struct{}, len(req.GetFilter().GetNodeIds()))
	for _, nodeID := range req.GetFilter().GetNodeIds() {
		allowed[nodeID] = struct{}{}
	}
	var jobs []*jobv1.Job
	for _, job := range f.jobs {
		if _, ok := allowed[job.GetNodeId()]; ok {
			jobs = append(jobs, job)
		}
	}

	return &jobv1.ListJobsResponse{Jobs: jobs}, nil
}

func (f *reconcileJDClient) ListProposals(_ context.Context, req *jobv1.ListProposalsRequest, _ ...grpc.CallOption) (*jobv1.ListProposalsResponse, error) {
	f.listProposalCalls = append(f.listProposalCalls, req)
	allowed := make(map[string]struct{}, len(req.GetFilter().GetJobIds()))
	for _, jobID := range req.GetFilter().GetJobIds() {
		allowed[jobID] = struct{}{}
	}
	var proposals []*jobv1.Proposal
	for _, proposal := range f.proposals {
		if _, ok := allowed[proposal.GetJobId()]; ok {
			proposals = append(proposals, proposal)
		}
	}

	return &jobv1.ListProposalsResponse{Proposals: proposals}, nil
}

func TestReconcileJobsWithJDApply(t *testing.T) {
	t.Parallel()

	const (
		alias          = shared.NOPAlias("chainlink-ccv-staging-0")
		verifierNodeID = "node_verifier"
		executorNodeID = "node_executor"
		oldJDJobID     = "job_old"
		newJDJobID     = "job_standalone"
		proposalID     = "prop_standalone"
	)

	path, spec := writeReconcileJobspec(t, alias)
	jobID := shared.JobID(fmt.Sprintf("%s-default-executor", alias))
	externalJobID := jobID.ToExternalJobID()
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ccvdeployment.SaveJob(ds, shared.JobInfo{
		JobID:         jobID,
		JDJobID:       oldJDJobID,
		ExternalJobID: externalJobID,
		NOPAlias:      alias,
		NodeID:        verifierNodeID,
		Mode:          shared.NOPModeCL,
		Spec:          strings.Replace(spec, "appConfig", "executorConfig", 1),
		Proposals: map[string]shared.ProposalRevision{
			"prop_old": {
				ProposalID: "prop_old",
				Revision:   7,
				Status:     shared.JobProposalStatusPending,
				Spec:       strings.Replace(spec, "appConfig", "executorConfig", 1),
			},
		},
	}))

	client := &reconcileJDClient{
		jobs: []*jobv1.Job{
			{Id: newJDJobID, Uuid: externalJobID, NodeId: executorNodeID},
			{Id: oldJDJobID, Uuid: externalJobID, NodeId: verifierNodeID},
		},
		proposals: []*jobv1.Proposal{
			{Id: proposalID, JobId: newJDJobID, Revision: 1, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: spec},
		},
	}
	env := reconcileTestEnvironment(t, client, ds, []string{verifierNodeID, executorNodeID})
	input := ReconcileJobsWithJDInput{Jobs: []ReconcileJobWithJD{{
		NOPAlias: alias, JobspecPath: path, NodeID: executorNodeID,
	}}}

	require.NoError(t, ReconcileJobsWithJD().VerifyPreconditions(env, input))
	out, err := ReconcileJobsWithJD().Apply(env, input)
	require.NoError(t, err)
	require.NotNil(t, out.DataStore)

	got, err := ccvdeployment.GetJob(out.DataStore.Seal(), alias, jobID)
	require.NoError(t, err)
	require.Equal(t, newJDJobID, got.JDJobID)
	require.Equal(t, executorNodeID, got.NodeID)
	require.Equal(t, shared.NOPModeStandalone, got.Mode)
	require.Equal(t, spec, got.Spec)
	require.Equal(t, proposalID, got.ActiveProposalID)
	require.Equal(t, map[string]shared.ProposalRevision{
		proposalID: {
			ProposalID: proposalID,
			Revision:   1,
			Status:     shared.JobProposalStatusApproved,
		},
	}, got.Proposals)

	original, err := ccvdeployment.GetJob(ds.Seal(), alias, jobID)
	require.NoError(t, err)
	require.Equal(t, oldJDJobID, original.JDJobID)
	require.Equal(t, verifierNodeID, original.NodeID)
	require.Equal(t, shared.NOPModeCL, original.Mode)

	require.Len(t, client.listJobsRequests, 1)
	require.Equal(t, []string{executorNodeID}, client.listJobsRequests[0].GetFilter().GetNodeIds())
	require.Len(t, client.listProposalCalls, 1)
	require.Equal(t, []string{newJDJobID}, client.listProposalCalls[0].GetFilter().GetJobIds())
}

func TestReconcileJobsWithJDApplyFailures(t *testing.T) {
	t.Parallel()

	const (
		alias      = shared.NOPAlias("chainlink-ccv-staging-0")
		nodeID     = "node_executor"
		jdJobID    = "job_standalone"
		proposalID = "prop_standalone"
	)

	tests := []struct {
		name       string
		jobs       []*jobv1.Job
		proposals  []*jobv1.Proposal
		mutateSpec func(string) string
		wantError  string
	}{
		{
			name:      "missing job",
			wantError: "found 0",
		},
		{
			name: "duplicate jobs",
			jobs: []*jobv1.Job{
				{Id: jdJobID, Uuid: "", NodeId: nodeID},
				{Id: "job_duplicate", Uuid: "", NodeId: nodeID},
			},
			wantError: "found 2",
		},
		{
			name:      "no proposals",
			jobs:      []*jobv1.Job{{Id: jdJobID, Uuid: "", NodeId: nodeID}},
			wantError: "has no proposals",
		},
		{
			name: "latest proposal pending",
			jobs: []*jobv1.Job{{Id: jdJobID, Uuid: "", NodeId: nodeID}},
			proposals: []*jobv1.Proposal{
				{Id: "prop_approved", JobId: jdJobID, Revision: 1, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED},
				{Id: proposalID, JobId: jdJobID, Revision: 2, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_PROPOSED},
			},
			wantError: "is not approved",
		},
		{
			name: "latest approved spec mismatch",
			jobs: []*jobv1.Job{{Id: jdJobID, Uuid: "", NodeId: nodeID}},
			proposals: []*jobv1.Proposal{
				{Id: proposalID, JobId: jdJobID, Revision: 1, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: "different"},
			},
			wantError: "does not match jobspec",
		},
		{
			name:       "CL mode spec rejected",
			mutateSpec: func(spec string) string { return strings.Replace(spec, "appConfig", "executorConfig", 1) },
			wantError:  "must contain appConfig and no executorConfig",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path, spec := writeReconcileJobspec(t, alias)
			externalJobID := shared.JobID(fmt.Sprintf("%s-default-executor", alias)).ToExternalJobID()
			if tt.mutateSpec != nil {
				mutated := tt.mutateSpec(spec)
				require.NoError(t, os.WriteFile(path, []byte(mutated), 0o600))
				spec = mutated
			}
			for _, job := range tt.jobs {
				if job.Uuid == "" {
					job.Uuid = externalJobID
				}
			}
			for _, proposal := range tt.proposals {
				if proposal.Spec == "" {
					proposal.Spec = spec
				}
			}
			client := &reconcileJDClient{jobs: tt.jobs, proposals: tt.proposals}
			env := reconcileTestEnvironment(t, client, datastore.NewMemoryDataStore(), []string{nodeID})

			out, err := ReconcileJobsWithJD().Apply(env, ReconcileJobsWithJDInput{Jobs: []ReconcileJobWithJD{{
				NOPAlias: alias, JobspecPath: path, NodeID: nodeID,
			}}})
			require.ErrorContains(t, err, tt.wantError)
			require.Nil(t, out.DataStore)
		})
	}
}

func TestReconcileJobsWithJDApplyIsAtomic(t *testing.T) {
	t.Parallel()

	const (
		firstAlias  = shared.NOPAlias("chainlink-ccv-staging-0")
		secondAlias = shared.NOPAlias("chainlink-ccv-staging-1")
		firstNode   = "node_executor_0"
		secondNode  = "node_executor_1"
	)

	firstPath, firstSpec := writeReconcileJobspec(t, firstAlias)
	firstJobID := shared.JobID(fmt.Sprintf("%s-default-executor", firstAlias))
	firstExternalID := firstJobID.ToExternalJobID()
	secondPath, _ := writeReconcileJobspec(t, secondAlias)
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ccvdeployment.SaveJob(ds, shared.JobInfo{
		JobID: firstJobID, JDJobID: "job_old", ExternalJobID: firstExternalID,
		NOPAlias: firstAlias, NodeID: "node_verifier", Mode: shared.NOPModeCL, Spec: firstSpec,
	}))
	client := &reconcileJDClient{jobs: []*jobv1.Job{{Id: "job_new", Uuid: firstExternalID, NodeId: firstNode}}}
	env := reconcileTestEnvironment(t, client, ds, []string{firstNode, secondNode})

	out, err := ReconcileJobsWithJD().Apply(env, ReconcileJobsWithJDInput{Jobs: []ReconcileJobWithJD{
		{NOPAlias: firstAlias, JobspecPath: firstPath, NodeID: firstNode},
		{NOPAlias: secondAlias, JobspecPath: secondPath, NodeID: secondNode},
	}})
	require.ErrorContains(t, err, "found 0")
	require.Nil(t, out.DataStore)

	original, getErr := ccvdeployment.GetJob(ds.Seal(), firstAlias, firstJobID)
	require.NoError(t, getErr)
	require.Equal(t, "job_old", original.JDJobID)
	require.Equal(t, shared.NOPModeCL, original.Mode)
	require.Empty(t, client.listProposalCalls)
}

func TestReconcileJobsWithJDVerifyPreconditions(t *testing.T) {
	t.Parallel()

	client := &reconcileJDClient{}
	path, _ := writeReconcileJobspec(t, "chainlink-ccv-staging-0")
	valid := ReconcileJobWithJD{NOPAlias: "chainlink-ccv-staging-0", JobspecPath: path, NodeID: "node_executor"}

	t.Run("JD required", func(t *testing.T) {
		t.Parallel()
		env := reconcileTestEnvironment(t, nil, datastore.NewMemoryDataStore(), []string{"node_executor"})
		err := ReconcileJobsWithJD().VerifyPreconditions(env, ReconcileJobsWithJDInput{Jobs: []ReconcileJobWithJD{valid}})
		require.ErrorContains(t, err, "offchain client")
	})

	t.Run("empty jobs", func(t *testing.T) {
		t.Parallel()
		env := reconcileTestEnvironment(t, client, datastore.NewMemoryDataStore(), []string{"node_executor"})
		err := ReconcileJobsWithJD().VerifyPreconditions(env, ReconcileJobsWithJDInput{})
		require.ErrorContains(t, err, "no jobs")
	})

	t.Run("node must belong to environment", func(t *testing.T) {
		t.Parallel()
		env := reconcileTestEnvironment(t, client, datastore.NewMemoryDataStore(), []string{"node_other"})
		err := ReconcileJobsWithJD().VerifyPreconditions(env, ReconcileJobsWithJDInput{Jobs: []ReconcileJobWithJD{valid}})
		require.ErrorContains(t, err, "not in the environment node list")
	})

	t.Run("duplicate jobs", func(t *testing.T) {
		t.Parallel()
		env := reconcileTestEnvironment(t, client, datastore.NewMemoryDataStore(), []string{"node_executor"})
		err := ReconcileJobsWithJD().VerifyPreconditions(env, ReconcileJobsWithJDInput{Jobs: []ReconcileJobWithJD{valid, valid}})
		require.ErrorContains(t, err, "duplicate nop_alias and jobspec_path")
	})
}

func reconcileTestEnvironment(t *testing.T, client foffchain.Client, ds *datastore.MemoryDataStore, nodeIDs []string) deployment.Environment {
	t.Helper()
	return deployment.Environment{
		Logger:    logger.Test(t),
		DataStore: ds.Seal(),
		NodeIDs:   nodeIDs,
		Offchain:  client,
		GetContext: func() context.Context {
			return t.Context()
		},
	}
}

func writeReconcileJobspec(t *testing.T, alias shared.NOPAlias) (string, string) {
	t.Helper()
	jobID := shared.JobID(fmt.Sprintf("%s-default-executor", alias))
	externalJobID := jobID.ToExternalJobID()
	spec := fmt.Sprintf(`schemaVersion = 1
type = "ccvexecutor"
name = %q
externalJobID = %q
appConfig = '''
executor_id = %q
'''
`, jobID, externalJobID, alias)
	path := filepath.Join(t.TempDir(), "executor.toml")
	require.NoError(t, os.WriteFile(path, []byte(spec), 0o600))

	return path, spec
}
