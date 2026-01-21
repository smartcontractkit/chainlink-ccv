package deployments

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

func TestSaveNOPJobSpec_PreservesOtherJobSpecsForSameNOP(t *testing.T) {
	ds := datastore.NewMemoryDataStore()

	// Save first job spec for nop-1
	err := SaveNOPJobSpec(ds, "nop-1", "nop-1-verifier-1", "verifier-job-spec-1")
	require.NoError(t, err)

	// Save second job spec for same nop-1
	err = SaveNOPJobSpec(ds, "nop-1", "nop-1-executor-1", "executor-job-spec-1")
	require.NoError(t, err)

	// Verify both job specs exist
	jobSpec1, err := GetNOPJobSpec(ds.Seal(), "nop-1", "nop-1-verifier-1")
	require.NoError(t, err)
	assert.Equal(t, "verifier-job-spec-1", jobSpec1)

	jobSpec2, err := GetNOPJobSpec(ds.Seal(), "nop-1", "nop-1-executor-1")
	require.NoError(t, err)
	assert.Equal(t, "executor-job-spec-1", jobSpec2)

	// Verify GetNOPJobSpecs returns both
	allSpecs, err := GetNOPJobSpecs(ds.Seal(), "nop-1")
	require.NoError(t, err)
	assert.Len(t, allSpecs, 2)
}

func TestSaveNOPJobSpec_PreservesOtherNOPJobSpecs(t *testing.T) {
	ds := datastore.NewMemoryDataStore()

	// Save job spec for nop-1
	err := SaveNOPJobSpec(ds, "nop-1", "nop-1-verifier", "nop-1-verifier-content")
	require.NoError(t, err)

	// Save job spec for nop-2
	err = SaveNOPJobSpec(ds, "nop-2", "nop-2-verifier", "nop-2-verifier-content")
	require.NoError(t, err)

	// Verify nop-1 job spec still exists
	jobSpec1, err := GetNOPJobSpec(ds.Seal(), "nop-1", "nop-1-verifier")
	require.NoError(t, err)
	assert.Equal(t, "nop-1-verifier-content", jobSpec1)

	// Verify nop-2 job spec exists
	jobSpec2, err := GetNOPJobSpec(ds.Seal(), "nop-2", "nop-2-verifier")
	require.NoError(t, err)
	assert.Equal(t, "nop-2-verifier-content", jobSpec2)
}

func TestSaveNOPJobSpec_UpdatesExistingJobSpec(t *testing.T) {
	ds := datastore.NewMemoryDataStore()

	// Save initial job spec
	err := SaveNOPJobSpec(ds, "nop-1", "nop-1-verifier", "original-content")
	require.NoError(t, err)

	// Update the same job spec
	err = SaveNOPJobSpec(ds, "nop-1", "nop-1-verifier", "updated-content")
	require.NoError(t, err)

	// Verify it was updated
	jobSpec, err := GetNOPJobSpec(ds.Seal(), "nop-1", "nop-1-verifier")
	require.NoError(t, err)
	assert.Equal(t, "updated-content", jobSpec)
}

func TestSaveNOPJobSpec_PreservesOtherOffchainConfigs(t *testing.T) {
	ds := datastore.NewMemoryDataStore()

	// Save an aggregator config first with actual data
	err := SaveAggregatorConfig(ds, "test-agg", &model.Committee{
		QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{
			"12345": {Threshold: 2},
		},
	})
	require.NoError(t, err)

	// Save a NOP job spec
	err = SaveNOPJobSpec(ds, "nop-1", "nop-1-verifier", "verifier-content")
	require.NoError(t, err)

	// Verify both exist - aggregator config should still be there
	cfg, err := GetAggregatorConfig(ds.Seal(), "test-agg")
	require.NoError(t, err, "aggregator config should be preserved")
	assert.Equal(t, uint8(2), cfg.QuorumConfigs["12345"].Threshold)

	jobSpec, err := GetNOPJobSpec(ds.Seal(), "nop-1", "nop-1-verifier")
	require.NoError(t, err)
	assert.Equal(t, "verifier-content", jobSpec)
}
