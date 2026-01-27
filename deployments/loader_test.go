package deployments

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

func TestSaveJob_PreservesOtherJobsForSameNOP(t *testing.T) {
	ds := datastore.NewMemoryDataStore()

	err := SaveJob(ds, shared.JobInfo{
		Spec:     "verifier-job-spec-1",
		JobID:    "nop-1-verifier-1",
		NOPAlias: "nop-1",
	})
	require.NoError(t, err)

	err = SaveJob(ds, shared.JobInfo{
		Spec:     "executor-job-spec-1",
		JobID:    "nop-1-executor-1",
		NOPAlias: "nop-1",
	})
	require.NoError(t, err)

	job1, err := GetJob(ds.Seal(), "nop-1", "nop-1-verifier-1")
	require.NoError(t, err)
	assert.Equal(t, "verifier-job-spec-1", job1.Spec)

	job2, err := GetJob(ds.Seal(), "nop-1", "nop-1-executor-1")
	require.NoError(t, err)
	assert.Equal(t, "executor-job-spec-1", job2.Spec)

	allJobs, err := GetJobsByNOP(ds.Seal(), "nop-1")
	require.NoError(t, err)
	assert.Len(t, allJobs, 2)
}

func TestSaveJob_PreservesOtherNOPJobs(t *testing.T) {
	ds := datastore.NewMemoryDataStore()

	err := SaveJob(ds, shared.JobInfo{
		Spec:     "nop-1-verifier-content",
		JobID:    "nop-1-verifier",
		NOPAlias: "nop-1",
	})
	require.NoError(t, err)

	err = SaveJob(ds, shared.JobInfo{
		Spec:     "nop-2-verifier-content",
		JobID:    "nop-2-verifier",
		NOPAlias: "nop-2",
	})
	require.NoError(t, err)

	job1, err := GetJob(ds.Seal(), "nop-1", "nop-1-verifier")
	require.NoError(t, err)
	assert.Equal(t, "nop-1-verifier-content", job1.Spec)

	job2, err := GetJob(ds.Seal(), "nop-2", "nop-2-verifier")
	require.NoError(t, err)
	assert.Equal(t, "nop-2-verifier-content", job2.Spec)
}

func TestSaveJob_UpdatesExistingJob(t *testing.T) {
	ds := datastore.NewMemoryDataStore()

	err := SaveJob(ds, shared.JobInfo{
		Spec:     "original-content",
		JobID:    "nop-1-verifier",
		NOPAlias: "nop-1",
	})
	require.NoError(t, err)

	err = SaveJob(ds, shared.JobInfo{
		Spec:             "updated-content",
		JobID:            "nop-1-verifier",
		NOPAlias:         "nop-1",
		ActiveProposalID: "prop-123",
	})
	require.NoError(t, err)

	job, err := GetJob(ds.Seal(), "nop-1", "nop-1-verifier")
	require.NoError(t, err)
	assert.Equal(t, "updated-content", job.Spec)
	assert.Equal(t, "prop-123", job.ActiveProposalID)
}

func TestSaveJob_PreservesOtherOffchainConfigs(t *testing.T) {
	ds := datastore.NewMemoryDataStore()

	err := SaveAggregatorConfig(ds, "test-agg", &model.Committee{
		QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{
			"12345": {Threshold: 2},
		},
	})
	require.NoError(t, err)

	err = SaveJob(ds, shared.JobInfo{
		Spec:     "verifier-content",
		JobID:    "nop-1-verifier",
		NOPAlias: "nop-1",
	})
	require.NoError(t, err)

	cfg, err := GetAggregatorConfig(ds.Seal(), "test-agg")
	require.NoError(t, err, "aggregator config should be preserved")
	assert.Equal(t, uint8(2), cfg.QuorumConfigs["12345"].Threshold)

	job, err := GetJob(ds.Seal(), "nop-1", "nop-1-verifier")
	require.NoError(t, err)
	assert.Equal(t, "verifier-content", job.Spec)
}

func TestJobInfo_LatestProposal_ReturnsHighestRevision(t *testing.T) {
	job := shared.JobInfo{
		JobID:    "test-job",
		NOPAlias: "nop-1",
		Proposals: map[string]shared.ProposalRevision{
			"prop-1": {ProposalID: "prop-1", Revision: 1, Status: shared.JobProposalStatusPending},
			"prop-2": {ProposalID: "prop-2", Revision: 3, Status: shared.JobProposalStatusApproved},
			"prop-3": {ProposalID: "prop-3", Revision: 2, Status: shared.JobProposalStatusRejected},
		},
	}

	latest := job.LatestProposal()
	require.NotNil(t, latest)
	assert.Equal(t, "prop-2", latest.ProposalID)
	assert.Equal(t, int64(3), latest.Revision)
}

func TestJobInfo_LatestStatus_ReturnsHighestRevisionStatus(t *testing.T) {
	job := shared.JobInfo{
		JobID:    "test-job",
		NOPAlias: "nop-1",
		Proposals: map[string]shared.ProposalRevision{
			"prop-1": {ProposalID: "prop-1", Revision: 1, Status: shared.JobProposalStatusPending},
			"prop-2": {ProposalID: "prop-2", Revision: 2, Status: shared.JobProposalStatusRejected},
		},
	}

	assert.Equal(t, shared.JobProposalStatusRejected, job.LatestStatus())
}

func TestJobInfo_IsRunning_ReturnsTrueWhenActiveProposalSet(t *testing.T) {
	job := shared.JobInfo{
		JobID:            "test-job",
		NOPAlias:         "nop-1",
		ActiveProposalID: "prop-123",
	}

	assert.True(t, job.IsRunning())
}

func TestJobInfo_IsRunning_ReturnsFalseWhenNoActiveProposal(t *testing.T) {
	job := shared.JobInfo{
		JobID:    "test-job",
		NOPAlias: "nop-1",
	}

	assert.False(t, job.IsRunning())
}
