package deployment

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

func TestSaveJobOmitsProposalSpecsFromMetadata(t *testing.T) {
	t.Parallel()

	spec := strings.Repeat("x", 96*1024)
	ds := datastore.NewMemoryDataStore()
	job := shared.JobInfo{
		JobID:            "job-1",
		NOPAlias:         "nop-1",
		Spec:             spec,
		ActiveProposalID: "p1",
		Proposals: map[string]shared.ProposalRevision{
			"p1": {ProposalID: "p1", Revision: 1, Status: shared.JobProposalStatusApproved, Spec: spec + "-active"},
			"p2": {ProposalID: "p2", Revision: 2, Status: shared.JobProposalStatusRejected, Spec: spec + "-orphaned"},
			"p3": {ProposalID: "p3", Revision: 3, Status: shared.JobProposalStatusPending, Spec: spec + "-latest"},
		},
	}
	require.NoError(t, SaveJob(ds, job))

	metadata, err := ds.EnvMetadata().Get()
	require.NoError(t, err)
	raw, err := json.Marshal(metadata.Metadata)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(raw), spec))
	require.Less(t, len(raw), 2*len(spec))

	stored, err := GetJob(ds.Seal(), job.NOPAlias, job.JobID)
	require.NoError(t, err)
	require.Equal(t, spec, stored.Spec)
	require.Len(t, stored.Proposals, 2)
	for _, proposal := range stored.Proposals {
		require.Empty(t, proposal.Spec)
	}
	require.Equal(t, shared.JobProposalStatusApproved, stored.Proposals["p1"].Status)
	require.Equal(t, int64(3), stored.Proposals["p3"].Revision)
}

func TestLegacyProposalSpecsAreDiscardedOnNextSave(t *testing.T) {
	t.Parallel()

	const legacySpec = "legacy-proposal-spec"
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ds.EnvMetadata().Set(datastore.EnvMetadata{Metadata: map[string]any{
		"offchainConfigs": map[string]any{
			"nopJobs": map[string]any{
				"nop-1": map[string]any{
					"job-1": map[string]any{
						"jobId":    "job-1",
						"nopAlias": "nop-1",
						"spec":     "current-spec",
						"proposals": map[string]any{
							"p1": map[string]any{
								"proposalId": "p1",
								"revision":   1,
								"status":     "approved",
								"spec":       legacySpec,
							},
						},
					},
				},
			},
		},
	}}))

	job, err := GetJob(ds.Seal(), "nop-1", "job-1")
	require.NoError(t, err)
	require.Equal(t, "current-spec", job.Spec)
	require.Empty(t, job.Proposals["p1"].Spec)
	require.NoError(t, SaveJob(ds, *job))

	metadata, err := ds.EnvMetadata().Get()
	require.NoError(t, err)
	raw, err := json.Marshal(metadata.Metadata)
	require.NoError(t, err)
	require.NotContains(t, string(raw), legacySpec)
	require.Contains(t, string(raw), "current-spec")
}
