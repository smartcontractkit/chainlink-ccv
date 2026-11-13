package sequences

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"

	"github.com/smartcontractkit/chainlink-ccv/deployment/operations/propose_jobs"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

func TestFilterChangedJobs(t *testing.T) {
	t.Parallel()

	desired := shared.JobInfo{JobID: "job-1", NOPAlias: "nop-1", Mode: shared.NOPModeStandalone, Spec: "desired"}
	recorded := func(jdSpec string) shared.JobInfo {
		job := desired
		job.JDJobID = "jd-1"
		job.NodeID = "node-1"
		job.Proposals = map[string]shared.ProposalRevision{
			"p1": {ProposalID: "p1", Revision: 1, Status: shared.JobProposalStatusApproved, Spec: jdSpec},
		}
		return job
	}
	stored := func(spec string, mode shared.NOPMode) shared.NOPJobs {
		return shared.NOPJobs{"nop-1": {"job-1": {JobID: "job-1", NOPAlias: "nop-1", Mode: mode, Spec: spec}}}
	}

	tests := []struct {
		name     string
		job      shared.JobInfo
		existing shared.NOPJobs
		targets  map[shared.JobID]string
		want     bool
	}{
		{name: "JD already has the desired spec", job: recorded("desired"), existing: stored("desired", shared.NOPModeStandalone)},
		{name: "JD has an out-of-band revision", job: recorded("manual"), existing: stored("desired", shared.NOPModeStandalone), want: true},
		{name: "JD spec unknown falls back to the stored spec", job: recorded(""), existing: stored("desired", shared.NOPModeStandalone)},
		{name: "JD spec unknown and stored spec changed", job: recorded(""), existing: stored("old", shared.NOPModeStandalone), want: true},
		{name: "no JD job recorded", job: desired, existing: stored("desired", shared.NOPModeStandalone), want: true},
		{name: "stored mode differs but JD has the desired spec", job: recorded("desired"), existing: stored("desired", shared.NOPModeCL)},
		{name: "stored mode differs and JD spec unknown", job: recorded(""), existing: stored("desired", shared.NOPModeCL), want: true},
		{name: "routed to a different node", job: recorded("desired"), existing: stored("desired", shared.NOPModeStandalone), targets: map[shared.JobID]string{"job-1": "node-2"}, want: true},
		{name: "routed to the recorded node", job: recorded("desired"), existing: stored("desired", shared.NOPModeStandalone), targets: map[shared.JobID]string{"job-1": "node-1"}},
		{name: "adopted JD job with the desired spec and no stored record", job: recorded("desired")},
		{name: "no stored record and JD spec unknown", job: recorded(""), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			changed := filterChangedJobs([]shared.JobInfo{tt.job}, tt.existing, tt.targets)
			if tt.want {
				require.Len(t, changed, 1)
			} else {
				require.Empty(t, changed)
			}
		})
	}
}

func TestUpdateJobsWithJDResponseStartsNewHistoryForNewJDJob(t *testing.T) {
	t.Parallel()

	jobs := []shared.JobInfo{
		{
			JobID: "moved", JDJobID: "jd-old", NodeID: "node-old", ActiveProposalID: "p-old",
			Proposals: map[string]shared.ProposalRevision{"p-old": {ProposalID: "p-old", Revision: 7, Status: shared.JobProposalStatusApproved}},
		},
		{
			JobID: "revised", JDJobID: "jd-same", NodeID: "node-same", ActiveProposalID: "p-1",
			Proposals: map[string]shared.ProposalRevision{"p-1": {ProposalID: "p-1", Revision: 1, Status: shared.JobProposalStatusApproved}},
		},
	}
	superseded := updateJobsWithJDResponse(jobs, []propose_jobs.ProposedJob{
		{InternalJobID: "moved", JobID: "jd-new", NodeID: "node-new", ProposalID: "p-new", Revision: 1},
		{InternalJobID: "revised", JobID: "jd-same", NodeID: "node-same", ProposalID: "p-2", Revision: 2},
	})

	require.Len(t, superseded, 1)
	require.Equal(t, "jd-old", superseded[0].JDJobID)
	require.Equal(t, "node-old", superseded[0].NodeID)

	require.Equal(t, "jd-new", jobs[0].JDJobID)
	require.Equal(t, "node-new", jobs[0].NodeID)
	require.Empty(t, jobs[0].ActiveProposalID)
	require.Len(t, jobs[0].Proposals, 1)
	require.Equal(t, shared.JobProposalStatusPending, jobs[0].LatestStatus())

	require.Equal(t, "p-1", jobs[1].ActiveProposalID)
	require.Len(t, jobs[1].Proposals, 2)
	require.Equal(t, "p-2", jobs[1].LatestProposal().ProposalID)
}

type jobsJDClient struct {
	jobs []*jobv1.Job
}

func (c *jobsJDClient) ListJobs(_ context.Context, req *jobv1.ListJobsRequest, _ ...grpc.CallOption) (*jobv1.ListJobsResponse, error) {
	var jobs []*jobv1.Job
	for _, job := range c.jobs {
		if slices.Contains(req.GetFilter().GetNodeIds(), job.GetNodeId()) {
			jobs = append(jobs, job)
		}
	}
	return &jobv1.ListJobsResponse{Jobs: jobs}, nil
}

func TestRetargetJobs(t *testing.T) {
	t.Parallel()

	recordedOn := func(jobID shared.JobID, jdJobID, nodeID string) shared.JobInfo {
		return shared.JobInfo{
			JobID: jobID, ExternalJobID: jobID.ToExternalJobID(), JDJobID: jdJobID, NodeID: nodeID, ActiveProposalID: "p-old",
			Proposals: map[string]shared.ProposalRevision{"p-old": {ProposalID: "p-old", Revision: 7}},
		}
	}
	client := &jobsJDClient{jobs: []*jobv1.Job{
		{Id: "jd-adopt", NodeId: "node-b", Uuid: shared.JobID("adopt").ToExternalJobID()},
		{Id: "jd-deleted", NodeId: "node-c", Uuid: shared.JobID("fresh").ToExternalJobID(), DeletedAt: timestamppb.Now()},
		{Id: "jd-dup-1", NodeId: "node-d", Uuid: shared.JobID("dup").ToExternalJobID()},
		{Id: "jd-dup-2", NodeId: "node-d", Uuid: shared.JobID("dup").ToExternalJobID()},
	}}
	jobs := []shared.JobInfo{
		recordedOn("adopt", "jd-old", "node-a"),
		recordedOn("fresh", "jd-old-2", "node-a"),
		recordedOn("stay", "jd-stay", "node-a"),
	}
	targets := map[shared.JobID]string{"adopt": "node-b", "fresh": "node-c", "stay": "node-a"}

	superseded, err := retargetJobs(t.Context(), client, jobs, targets)
	require.NoError(t, err)
	require.Len(t, superseded, 2)
	require.Equal(t, "jd-old", superseded[0].JDJobID)

	require.Equal(t, "jd-adopt", jobs[0].JDJobID)
	require.Equal(t, "node-b", jobs[0].NodeID)
	require.Empty(t, jobs[0].Proposals)
	require.Empty(t, jobs[0].ActiveProposalID)
	require.Empty(t, jobs[1].JDJobID, "a deleted JD job is not adopted")
	require.Equal(t, "node-c", jobs[1].NodeID)
	require.Equal(t, "jd-stay", jobs[2].JDJobID)
	require.Equal(t, "p-old", jobs[2].ActiveProposalID)

	_, err = retargetJobs(t.Context(), client, []shared.JobInfo{recordedOn("dup", "", "")}, map[shared.JobID]string{"dup": "node-d"})
	require.ErrorContains(t, err, "2 live JD jobs")
}

type proposalsJDClient struct {
	shared.JDClient
	proposals map[string][]*jobv1.Proposal
	err       error
}

func (c *proposalsJDClient) ListProposals(_ context.Context, req *jobv1.ListProposalsRequest, _ ...grpc.CallOption) (*jobv1.ListProposalsResponse, error) {
	if c.err != nil {
		return nil, c.err
	}
	var proposals []*jobv1.Proposal
	for _, jobID := range req.GetFilter().GetJobIds() {
		proposals = append(proposals, c.proposals[jobID]...)
	}
	return &jobv1.ListProposalsResponse{Proposals: proposals}, nil
}

func TestRefreshJobsFromJD(t *testing.T) {
	t.Parallel()

	client := &proposalsJDClient{proposals: map[string][]*jobv1.Proposal{
		"jd-1": {
			{Id: "p1", JobId: "jd-1", Revision: 1, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: "s1"},
			{Id: "p2", JobId: "jd-1", Revision: 2, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: "s2"},
			{Id: "p3", JobId: "jd-1", Revision: 3, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_PROPOSED, Spec: "s3"},
		},
	}}
	jobs := []shared.JobInfo{
		{
			JobID: "tracked", JDJobID: "jd-1", ActiveProposalID: "stale",
			Proposals: map[string]shared.ProposalRevision{"stale": {ProposalID: "stale", Revision: 9, Status: shared.JobProposalStatusApproved}},
		},
		{JobID: "gone", JDJobID: "jd-deleted", Proposals: map[string]shared.ProposalRevision{"x": {ProposalID: "x"}}},
		{JobID: "untracked"},
	}

	require.NoError(t, refreshJobsFromJD(t.Context(), client, jobs))

	require.Equal(t, "p2", jobs[0].ActiveProposalID)
	require.Len(t, jobs[0].Proposals, 3)
	require.Equal(t, "s3", jobs[0].LatestProposal().Spec)
	require.Equal(t, shared.JobProposalStatusPending, jobs[0].LatestStatus())

	require.Empty(t, jobs[1].JDJobID, "a JD job that JD no longer has must be proposed again")
	require.Empty(t, jobs[1].Proposals)
	require.Empty(t, jobs[2].JDJobID)

	client.err = errors.New("unavailable")
	require.ErrorContains(t, refreshJobsFromJD(t.Context(), client, jobs[:1]), "unavailable")
}
