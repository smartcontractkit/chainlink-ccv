package sequences

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

func TestFilterChangedJobsUsesCanonicalSpec(t *testing.T) {
	t.Parallel()

	newJobs := []shared.JobInfo{{
		JobID:    "job-1",
		NOPAlias: "nop-1",
		Mode:     shared.NOPModeCL,
		Spec:     "new-spec",
	}}
	existing := shared.JobInfo{
		JobID:    "job-1",
		NOPAlias: "nop-1",
		Mode:     shared.NOPModeCL,
		Spec:     "new-spec",
		Proposals: map[string]shared.ProposalRevision{
			"p1": {ProposalID: "p1", Revision: 1, Status: shared.JobProposalStatusApproved},
		},
	}

	t.Run("unchanged spec without proposal spec copies", func(t *testing.T) {
		jobs := shared.NOPJobs{"nop-1": {"job-1": existing}}
		require.Empty(t, filterChangedJobs(newJobs, jobs))
	})

	t.Run("changed canonical spec", func(t *testing.T) {
		changed := existing
		changed.Spec = "old-spec"
		jobs := shared.NOPJobs{"nop-1": {"job-1": changed}}
		require.Len(t, filterChangedJobs(newJobs, jobs), 1)
	})

	t.Run("unchanged spec still requires a proposal", func(t *testing.T) {
		unproposed := existing
		unproposed.Proposals = nil
		jobs := shared.NOPJobs{"nop-1": {"job-1": unproposed}}
		require.Len(t, filterChangedJobs(newJobs, jobs), 1)
	})
}
