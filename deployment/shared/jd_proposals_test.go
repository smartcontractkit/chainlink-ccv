package shared

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
)

func TestSetProposalsFromJD(t *testing.T) {
	t.Parallel()

	job := JobInfo{
		JDJobID:          "jd-1",
		ActiveProposalID: "stale",
		Proposals:        map[string]ProposalRevision{"stale": {ProposalID: "stale", Revision: 9}},
	}
	job.SetProposalsFromJD([]*jobv1.Proposal{
		{Id: "p2", JobId: "jd-1", Revision: 2, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: "s2"},
		{Id: "p1", JobId: "jd-1", Revision: 1, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED},
		{Id: "p3", JobId: "jd-1", Revision: 3, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_CANCELLED},
		{Id: "other", JobId: "jd-2", Revision: 8, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED},
		{Id: "", JobId: "jd-1", Revision: 4},
	})

	require.Equal(t, []string{"p1", "p2", "p3"}, slices.Sorted(maps.Keys(job.Proposals)))
	require.Equal(t, "p2", job.ActiveProposalID)
	require.Equal(t, "s2", job.Proposals["p2"].Spec)
	require.Equal(t, JobProposalStatusRevoked, job.LatestStatus())

	job.SetProposalsFromJD(nil)
	require.Empty(t, job.Proposals)
	require.Empty(t, job.ActiveProposalID)
}
