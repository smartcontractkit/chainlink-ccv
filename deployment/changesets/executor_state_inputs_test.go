package changesets

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

const testExecutorQualifier = "default-executor"

// seedExecutorJobs builds real executor job specs from the given pool (via the
// production buildExecutorJobSpecs path) and persists them to a fresh datastore,
// returning the sealed store. This exercises the exact emit→persist→reconstruct
// round-trip the resolver must be faithful to.
func seedExecutorJobs(t *testing.T, sel uint64, pool ExecutorPoolInput, indexer []string) datastore.DataStore {
	t.Helper()

	adapterCfgs := map[string]executor.ChainConfiguration{
		strconv.FormatUint(sel, 10): {
			DestinationChainConfig: chainaccess.DestinationChainConfig{
				OffRampAddress: "0xofframp",
				RmnAddress:     "0xrmn",
			},
			DefaultExecutorAddress: "0xexec",
		},
	}

	specs, _, err := buildExecutorJobSpecs(
		adapterCfgs,
		testExecutorQualifier,
		nil, // all NOPs
		pool,
		indexer,
		"", // pyroscope
	)
	require.NoError(t, err)

	ds := datastore.NewMemoryDataStore()
	for alias, byJob := range specs {
		for jobID, spec := range byJob {
			require.NoError(t, ccvdeployment.SaveJob(ds, shared.JobInfo{
				JobID:    jobID,
				NOPAlias: alias,
				Spec:     spec,
			}))
		}
	}
	return ds.Seal()
}

func samplePool(sel uint64) ExecutorPoolInput {
	return ExecutorPoolInput{
		ChainConfigs: map[uint64]ChainExecutorPoolMembership{
			sel: {
				NOPAliases:        []shared.NOPAlias{"nop1", "nop2"},
				ExecutionInterval: 30 * time.Second,
			},
		},
		IndexerQueryLimit: 100,
		BackoffDuration:   15 * time.Second,
		LookbackWindow:    time.Hour,
		ReaderCacheExpiry: 5 * time.Minute,
		MaxRetryDuration:  8 * time.Hour,
		WorkerCount:       4,
		NtpServer:         "time.google.com",
	}
}

func TestExecutorPoolInputFromState_RoundTrip(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	want := samplePool(sel)
	ds := seedExecutorJobs(t, sel, want, []string{"http://indexer:1"})

	got, extras, err := ExecutorPoolInputFromState(ds, testExecutorQualifier)
	require.NoError(t, err)

	// Per-chain membership + interval recovered.
	require.Contains(t, got.ChainConfigs, sel)
	assert.Equal(t, []shared.NOPAlias{"nop1", "nop2"}, got.ChainConfigs[sel].NOPAliases)
	assert.Equal(t, 30*time.Second, got.ChainConfigs[sel].ExecutionInterval)

	// Pool-wide tuning recovered.
	assert.Equal(t, uint64(100), got.IndexerQueryLimit)
	assert.Equal(t, 15*time.Second, got.BackoffDuration)
	assert.Equal(t, time.Hour, got.LookbackWindow)
	assert.Equal(t, 5*time.Minute, got.ReaderCacheExpiry)
	assert.Equal(t, 8*time.Hour, got.MaxRetryDuration)
	assert.Equal(t, 4, got.WorkerCount)
	assert.Equal(t, "time.google.com", got.NtpServer)

	// Connection settings recovered as extras.
	assert.Equal(t, []string{"http://indexer:1"}, extras.IndexerAddress)
}

func TestExecutorPoolInputFromState_ErrorsOnJobDrift(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector

	adapterCfgs := map[string]executor.ChainConfiguration{
		strconv.FormatUint(sel, 10): {
			DestinationChainConfig: chainaccess.DestinationChainConfig{OffRampAddress: "0xofframp", RmnAddress: "0xrmn"},
			DefaultExecutorAddress: "0xexec",
		},
	}
	poolA := samplePool(sel) // execution interval 30s
	poolB := samplePool(sel)
	poolB.ChainConfigs[sel] = ChainExecutorPoolMembership{
		NOPAliases:        []shared.NOPAlias{"nop1", "nop2"},
		ExecutionInterval: 60 * time.Second, // drift
	}

	specsA, _, err := buildExecutorJobSpecs(adapterCfgs, testExecutorQualifier, nil, poolA, []string{"http://i"}, "")
	require.NoError(t, err)
	specsB, _, err := buildExecutorJobSpecs(adapterCfgs, testExecutorQualifier, nil, poolB, []string{"http://i"}, "")
	require.NoError(t, err)

	ds := datastore.NewMemoryDataStore()
	save := func(alias shared.NOPAlias, specs shared.NOPJobSpecs) {
		for jobID, spec := range specs[alias] {
			require.NoError(t, ccvdeployment.SaveJob(ds, shared.JobInfo{JobID: jobID, NOPAlias: alias, Spec: spec}))
		}
	}
	save("nop1", specsA) // 30s
	save("nop2", specsB) // 60s — diverges

	_, _, err = ExecutorPoolInputFromState(ds.Seal(), testExecutorQualifier)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "diverges")
}

func TestExecutorPoolInputFromState_BootstrapEmpty(t *testing.T) {
	pool, extras, err := ExecutorPoolInputFromState(datastore.NewMemoryDataStore().Seal(), testExecutorQualifier)
	require.NoError(t, err)
	assert.Empty(t, pool.ChainConfigs)
	assert.Empty(t, extras.IndexerAddress)
}

func TestApplyExecutorConfigInputFromState_BuildsReadyInput(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	ds := seedExecutorJobs(t, sel, samplePool(sel), []string{"http://indexer:1"})

	in, err := ApplyExecutorConfigInputFromState(ds, testExecutorQualifier, ExecutorConfigFromStateOptions{
		ModeByNOP:          map[shared.NOPAlias]shared.NOPMode{"nop2": shared.NOPModeStandalone},
		RevokeOrphanedJobs: true,
	})
	require.NoError(t, err)

	assert.Equal(t, testExecutorQualifier, in.ExecutorQualifier)
	assert.Equal(t, []string{"http://indexer:1"}, in.IndexerAddress)
	assert.True(t, in.RevokeOrphanedJobs)
	require.Contains(t, in.Pool.ChainConfigs, sel)
	assert.Equal(t, []shared.NOPAlias{"nop1", "nop2"}, in.Pool.ChainConfigs[sel].NOPAliases)

	// NOPs built from pool membership, with the mode override applied.
	require.Len(t, in.NOPs, 2)
	modeByAlias := map[shared.NOPAlias]shared.NOPMode{}
	for _, n := range in.NOPs {
		modeByAlias[n.Alias] = n.Mode
	}
	assert.Equal(t, shared.NOPModeCL, modeByAlias["nop1"])
	assert.Equal(t, shared.NOPModeStandalone, modeByAlias["nop2"])

	// IndexerAddress override takes effect when supplied.
	in2, err := ApplyExecutorConfigInputFromState(ds, testExecutorQualifier, ExecutorConfigFromStateOptions{
		IndexerAddress: []string{"http://override:9"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"http://override:9"}, in2.IndexerAddress)
}
