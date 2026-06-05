package changesets

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

func newEmptyExecutorRegistry() *adapters.Registry {
	return adapters.GetRegistry()
}

func sampleExecutorPool(sel uint64, aliases ...shared.NOPAlias) ExecutorPoolInput {
	return ExecutorPoolInput{
		ChainConfigs: map[uint64]ChainExecutorPoolMembership{
			sel: {
				NOPAliases:        aliases,
				ExecutionInterval: 5 * time.Second,
			},
		},
		IndexerQueryLimit: 100,
		WorkerCount:       2,
	}
}

func TestApplyExecutorConfig_Validation_RequiresQualifier(t *testing.T) {
	cs := ApplyExecutorConfig(newEmptyExecutorRegistry())
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyExecutorConfigInput{
		NOPs:           []NOPInput{{Alias: "nop1"}},
		IndexerAddress: []string{"indexer:1234"},
		Pool:           sampleExecutorPool(chainsel.TEST_90000001.Selector, "nop1"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "executor qualifier is required")
}

func TestApplyExecutorConfig_Validation_RequiresNOPs(t *testing.T) {
	cs := ApplyExecutorConfig(newEmptyExecutorRegistry())
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyExecutorConfigInput{
		ExecutorQualifier: "default-executor",
		IndexerAddress:    []string{"indexer:1234"},
		Pool:              sampleExecutorPool(chainsel.TEST_90000001.Selector, "nop1"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one NOP is required")
}

func TestApplyExecutorConfig_Validation_RequiresIndexerAddress(t *testing.T) {
	cs := ApplyExecutorConfig(newEmptyExecutorRegistry())
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyExecutorConfigInput{
		ExecutorQualifier: "default-executor",
		NOPs:              []NOPInput{{Alias: "nop1"}},
		Pool:              sampleExecutorPool(chainsel.TEST_90000001.Selector, "nop1"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "indexer address is required")
}

func TestApplyExecutorConfig_Validation_RequiresPoolChainConfigs(t *testing.T) {
	cs := ApplyExecutorConfig(newEmptyExecutorRegistry())
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyExecutorConfigInput{
		ExecutorQualifier: "default-executor",
		NOPs:              []NOPInput{{Alias: "nop1"}},
		IndexerAddress:    []string{"indexer:1234"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ChainConfigs")
}

func TestApplyExecutorConfig_Validation_DuplicateNOPAliasRejected(t *testing.T) {
	cs := ApplyExecutorConfig(newEmptyExecutorRegistry())
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyExecutorConfigInput{
		ExecutorQualifier: "default-executor",
		NOPs:              []NOPInput{{Alias: "nop1"}, {Alias: "nop1"}},
		IndexerAddress:    []string{"indexer:1234"},
		Pool:              sampleExecutorPool(chainsel.TEST_90000001.Selector, "nop1"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `duplicate NOP alias "nop1"`)
}

func TestApplyExecutorConfig_Validation_PoolReferencesUnknownNOPRejected(t *testing.T) {
	cs := ApplyExecutorConfig(newEmptyExecutorRegistry())
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyExecutorConfigInput{
		ExecutorQualifier: "default-executor",
		NOPs:              []NOPInput{{Alias: "nop1"}},
		IndexerAddress:    []string{"indexer:1234"},
		Pool:              sampleExecutorPool(chainsel.TEST_90000001.Selector, "nopGhost"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown NOP alias "nopGhost"`)
}

func TestApplyExecutorConfig_Validation_TargetNOPMustBeInPool(t *testing.T) {
	cs := ApplyExecutorConfig(newEmptyExecutorRegistry())
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyExecutorConfigInput{
		ExecutorQualifier: "default-executor",
		NOPs:              []NOPInput{{Alias: "nop1"}, {Alias: "nop2"}},
		IndexerAddress:    []string{"indexer:1234"},
		Pool:              sampleExecutorPool(chainsel.TEST_90000001.Selector, "nop1"),
		TargetNOPs:        []shared.NOPAlias{"nop2"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `NOP alias "nop2" not found in executor pool`)
}

func TestApplyExecutorConfig_Validation_ProductionRejectsPyroscope(t *testing.T) {
	cs := ApplyExecutorConfig(newEmptyExecutorRegistry())
	err := cs.VerifyPreconditions(deployment.Environment{Name: "mainnet"}, ApplyExecutorConfigInput{
		ExecutorQualifier: "default-executor",
		NOPs:              []NOPInput{{Alias: "nop1"}},
		IndexerAddress:    []string{"indexer:1234"},
		Pool:              sampleExecutorPool(chainsel.TEST_90000001.Selector, "nop1"),
		PyroscopeURL:      "http://pyroscope.example",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pyroscope URL is not supported for production")
}

func TestApplyExecutorConfig_Validation_AcceptsValidImperativeInput(t *testing.T) {
	cs := ApplyExecutorConfig(newEmptyExecutorRegistry())
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyExecutorConfigInput{
		ExecutorQualifier: "default-executor",
		NOPs:              []NOPInput{{Alias: "nop1", Mode: shared.NOPModeCL}},
		IndexerAddress:    []string{"indexer:1234"},
		Pool:              sampleExecutorPool(chainsel.TEST_90000001.Selector, "nop1"),
	})
	require.NoError(t, err)
}

// ---- pure helpers ----

func TestExecutorPoolNOPAliases_DedupsAndSorts(t *testing.T) {
	pool := ExecutorPoolInput{
		ChainConfigs: map[uint64]ChainExecutorPoolMembership{
			1: {NOPAliases: []shared.NOPAlias{"nop2", "nop1"}},
			2: {NOPAliases: []shared.NOPAlias{"nop1", "nop3"}},
		},
	}
	got := executorPoolNOPAliases(pool)
	assert.Equal(t, []shared.NOPAlias{"nop1", "nop2", "nop3"}, got)
}

func TestRequiredChainsForExecutorNOP_ReturnsParticipatingChainsSorted(t *testing.T) {
	got := requiredChainsForExecutorNOP("nop1", ExecutorPoolInput{
		ChainConfigs: map[uint64]ChainExecutorPoolMembership{
			3: {NOPAliases: []shared.NOPAlias{"nop1"}},
			1: {NOPAliases: []shared.NOPAlias{"nop1", "nop2"}},
			2: {NOPAliases: []shared.NOPAlias{"nop2"}},
		},
	})
	assert.Equal(t, []uint64{1, 3}, got)
}
