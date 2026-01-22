package deployments_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/deployments"
)

func TestLoadEnvironmentTopology_LoadsValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "env.toml")

	configContent := `
indexer_address = "http://indexer:8100"
pyroscope_url = "http://pyroscope:4040"

[monitoring]
Enabled = true
Type = "beholder"

[monitoring.Beholder]
InsecureConnection = true
OtelExporterHTTPEndpoint = "otel:4318"
MetricReaderInterval = 5
TraceSampleRatio = 1.0
TraceBatchTimeout = 10

[executor_pools.default]
nop_aliases = ["nop-1", "nop-2"]
execution_interval = "15s"

[[nop_topology.nops]]
alias = "nop-1"
name = "NOP One"

[[nop_topology.nops]]
alias = "nop-2"
name = "NOP Two"

[nop_topology.committees.default]
qualifier = "default"

[nop_topology.committees.default.chain_configs."16015286601757825753"]
nop_aliases = ["nop-1", "nop-2"]
threshold = 2

[[nop_topology.committees.default.aggregators]]
name = "instance-1"
address = "aggregator-1:443"
insecure_connection = false
`
	err := os.WriteFile(configPath, []byte(configContent), 0o600)
	require.NoError(t, err)

	cfg, err := deployments.LoadEnvironmentTopology(configPath)
	require.NoError(t, err)

	assert.Equal(t, "http://indexer:8100", cfg.IndexerAddress)
	assert.Equal(t, "http://pyroscope:4040", cfg.PyroscopeURL)
	assert.True(t, cfg.Monitoring.Enabled)
	assert.Equal(t, "beholder", cfg.Monitoring.Type)

	require.Len(t, cfg.NOPTopology.NOPs, 2)
	nop1, ok := cfg.NOPTopology.GetNOP("nop-1")
	require.True(t, ok)
	assert.Equal(t, "NOP One", nop1.Name)
	nop2, ok := cfg.NOPTopology.GetNOP("nop-2")
	require.True(t, ok)
	assert.Equal(t, "NOP Two", nop2.Name)

	require.Len(t, cfg.NOPTopology.Committees, 1)
	committee := cfg.NOPTopology.Committees["default"]
	assert.Equal(t, "default", committee.Qualifier)
	require.Len(t, committee.Aggregators, 1)
	assert.Equal(t, "instance-1", committee.Aggregators[0].Name)

	require.Len(t, cfg.ExecutorPools, 1)
	pool := cfg.ExecutorPools["default"]
	assert.Equal(t, []string{"nop-1", "nop-2"}, pool.NOPAliases)
	assert.Equal(t, 15*time.Second, pool.ExecutionInterval)
}

func TestWriteEnvironmentTopology_WritesValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "env.toml")

	cfg := deployments.EnvironmentTopology{
		IndexerAddress: "http://indexer:8100",
		PyroscopeURL:   "http://pyroscope:4040",
		Monitoring: deployments.MonitoringConfig{
			Enabled: true,
			Type:    "beholder",
			Beholder: deployments.BeholderConfig{
				InsecureConnection:       true,
				OtelExporterHTTPEndpoint: "otel:4318",
				MetricReaderInterval:     5,
				TraceSampleRatio:         1.0,
				TraceBatchTimeout:        10,
			},
		},
		NOPTopology: deployments.NOPTopology{
			NOPs: []deployments.NOPConfig{
				{Alias: "nop-1", Name: "NOP One"},
				{Alias: "nop-2", Name: "NOP Two"},
			},
			Committees: map[string]deployments.CommitteeConfig{
				"default": {
					Qualifier: "default",
					ChainConfigs: map[string]deployments.ChainCommitteeConfig{
						"16015286601757825753": {NOPAliases: []string{"nop-1", "nop-2"}, Threshold: 2},
					},
					Aggregators: []deployments.AggregatorConfig{
						{Name: "instance-1", Address: "aggregator-1:443"},
					},
				},
			},
		},
		ExecutorPools: map[string]deployments.ExecutorPoolConfig{
			"default": {
				NOPAliases:        []string{"nop-1", "nop-2"},
				ExecutionInterval: 15 * time.Second,
			},
		},
	}

	err := deployments.WriteEnvironmentTopology(configPath, cfg)
	require.NoError(t, err)

	loaded, err := deployments.LoadEnvironmentTopology(configPath)
	require.NoError(t, err)

	assert.Equal(t, cfg.IndexerAddress, loaded.IndexerAddress)
	assert.Equal(t, cfg.PyroscopeURL, loaded.PyroscopeURL)
	assert.Len(t, loaded.NOPTopology.NOPs, 2)
	assert.Len(t, loaded.NOPTopology.Committees, 1)
	assert.Len(t, loaded.ExecutorPools, 1)
}

func TestEnvironmentTopology_GetNOPsForPool(t *testing.T) {
	cfg := deployments.EnvironmentTopology{
		IndexerAddress: "http://indexer:8100",
		NOPTopology: deployments.NOPTopology{
			NOPs: []deployments.NOPConfig{
				{Alias: "nop-1", Name: "NOP One"},
				{Alias: "nop-2", Name: "NOP Two"},
			},
			Committees: map[string]deployments.CommitteeConfig{},
		},
		ExecutorPools: map[string]deployments.ExecutorPoolConfig{
			"default": {NOPAliases: []string{"nop-1", "nop-2"}},
		},
	}

	nops, err := cfg.GetNOPsForPool("default")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"nop-1", "nop-2"}, nops)

	_, err = cfg.GetNOPsForPool("nonexistent")
	require.Error(t, err)
}

func TestEnvironmentTopology_GetNOPsForCommittee(t *testing.T) {
	cfg := deployments.EnvironmentTopology{
		IndexerAddress: "http://indexer:8100",
		NOPTopology: deployments.NOPTopology{
			NOPs: []deployments.NOPConfig{
				{Alias: "nop-1", Name: "NOP One"},
				{Alias: "nop-2", Name: "NOP Two"},
				{Alias: "nop-3", Name: "NOP Three"},
			},
			Committees: map[string]deployments.CommitteeConfig{
				"default": {
					Qualifier: "default",
					ChainConfigs: map[string]deployments.ChainCommitteeConfig{
						"123": {NOPAliases: []string{"nop-1", "nop-2"}, Threshold: 2},
						"456": {NOPAliases: []string{"nop-2", "nop-3"}, Threshold: 2},
					},
					Aggregators: []deployments.AggregatorConfig{{Name: "agg", Address: "addr"}},
				},
			},
		},
		ExecutorPools: map[string]deployments.ExecutorPoolConfig{},
	}

	nops, err := cfg.GetNOPsForCommittee("default")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"nop-1", "nop-2", "nop-3"}, nops)

	_, err = cfg.GetNOPsForCommittee("nonexistent")
	require.Error(t, err)
}

func TestEnvironmentTopology_GetCommitteesForNOP(t *testing.T) {
	cfg := deployments.EnvironmentTopology{
		IndexerAddress: "http://indexer:8100",
		NOPTopology: deployments.NOPTopology{
			NOPs: []deployments.NOPConfig{
				{Alias: "nop-1", Name: "NOP One"},
			},
			Committees: map[string]deployments.CommitteeConfig{
				"committee-a": {
					Qualifier: "committee-a",
					ChainConfigs: map[string]deployments.ChainCommitteeConfig{
						"123": {NOPAliases: []string{"nop-1"}, Threshold: 1},
					},
					Aggregators: []deployments.AggregatorConfig{{Name: "agg", Address: "addr"}},
				},
				"committee-b": {
					Qualifier: "committee-b",
					ChainConfigs: map[string]deployments.ChainCommitteeConfig{
						"456": {NOPAliases: []string{"nop-1"}, Threshold: 1},
					},
					Aggregators: []deployments.AggregatorConfig{{Name: "agg", Address: "addr"}},
				},
			},
		},
		ExecutorPools: map[string]deployments.ExecutorPoolConfig{},
	}

	committees := cfg.GetCommitteesForNOP("nop-1")
	assert.ElementsMatch(t, []string{"committee-a", "committee-b"}, committees)

	committees = cfg.GetCommitteesForNOP("nonexistent")
	assert.Empty(t, committees)
}

func TestEnvironmentTopology_GetPoolsForNOP(t *testing.T) {
	cfg := deployments.EnvironmentTopology{
		IndexerAddress: "http://indexer:8100",
		NOPTopology: deployments.NOPTopology{
			NOPs: []deployments.NOPConfig{
				{Alias: "nop-1", Name: "NOP One"},
			},
			Committees: map[string]deployments.CommitteeConfig{},
		},
		ExecutorPools: map[string]deployments.ExecutorPoolConfig{
			"pool-a": {NOPAliases: []string{"nop-1"}},
			"pool-b": {NOPAliases: []string{"nop-1", "nop-2"}},
		},
	}

	pools := cfg.GetPoolsForNOP("nop-1")
	assert.ElementsMatch(t, []string{"pool-a", "pool-b"}, pools)

	pools = cfg.GetPoolsForNOP("nonexistent")
	assert.Empty(t, pools)
}

func TestEnvironmentTopology_Validate_RequiresIndexerAddress(t *testing.T) {
	cfg := deployments.EnvironmentTopology{
		IndexerAddress: "",
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "indexer_address is required")
}

func TestEnvironmentTopology_Validate_DuplicateNOPAlias(t *testing.T) {
	cfg := deployments.EnvironmentTopology{
		IndexerAddress: "http://indexer:8100",
		NOPTopology: deployments.NOPTopology{
			NOPs: []deployments.NOPConfig{
				{Alias: "nop-1", Name: "NOP One"},
				{Alias: "nop-1", Name: "Duplicate NOP"},
			},
			Committees: map[string]deployments.CommitteeConfig{},
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate NOP alias")
}

func TestEnvironmentTopology_Validate_CommitteeReferencesUnknownNOP(t *testing.T) {
	cfg := deployments.EnvironmentTopology{
		IndexerAddress: "http://indexer:8100",
		NOPTopology: deployments.NOPTopology{
			NOPs: []deployments.NOPConfig{
				{Alias: "nop-1", Name: "NOP One"},
			},
			Committees: map[string]deployments.CommitteeConfig{
				"default": {
					Qualifier: "default",
					ChainConfigs: map[string]deployments.ChainCommitteeConfig{
						"123": {NOPAliases: []string{"nop-1", "unknown-nop"}, Threshold: 2},
					},
					Aggregators: []deployments.AggregatorConfig{{Name: "agg", Address: "addr"}},
				},
			},
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown NOP alias")
}

func TestEnvironmentTopology_Validate_ThresholdExceedsNOPCount(t *testing.T) {
	cfg := deployments.EnvironmentTopology{
		IndexerAddress: "http://indexer:8100",
		NOPTopology: deployments.NOPTopology{
			NOPs: []deployments.NOPConfig{
				{Alias: "nop-1", Name: "NOP One"},
			},
			Committees: map[string]deployments.CommitteeConfig{
				"default": {
					Qualifier: "default",
					ChainConfigs: map[string]deployments.ChainCommitteeConfig{
						"123": {NOPAliases: []string{"nop-1"}, Threshold: 5},
					},
					Aggregators: []deployments.AggregatorConfig{{Name: "agg", Address: "addr"}},
				},
			},
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "threshold 5 exceeds NOP count 1")
}

func TestNOPTopology_GetNOPIndex_ReturnsCorrectIndex(t *testing.T) {
	topology := &deployments.NOPTopology{
		NOPs: []deployments.NOPConfig{
			{Alias: "nop-a", Name: "NOP A"},
			{Alias: "nop-b", Name: "NOP B"},
			{Alias: "nop-c", Name: "NOP C"},
		},
	}

	idx, ok := topology.GetNOPIndex("nop-a")
	require.True(t, ok)
	assert.Equal(t, 0, idx)

	idx, ok = topology.GetNOPIndex("nop-b")
	require.True(t, ok)
	assert.Equal(t, 1, idx)

	idx, ok = topology.GetNOPIndex("nop-c")
	require.True(t, ok)
	assert.Equal(t, 2, idx)

	_, ok = topology.GetNOPIndex("nonexistent")
	assert.False(t, ok)
}

func TestNOPTopology_SetNOPSignerAddress(t *testing.T) {
	topology := &deployments.NOPTopology{
		NOPs: []deployments.NOPConfig{
			{Alias: "nop-1", Name: "NOP One"},
			{Alias: "nop-2", Name: "NOP Two"},
		},
	}

	ok := topology.SetNOPSignerAddress("nop-1", chainsel.FamilyEVM, "0x123")
	require.True(t, ok)

	nop, ok := topology.GetNOP("nop-1")
	require.True(t, ok)
	assert.Equal(t, "0x123", nop.SignerAddressByFamily[chainsel.FamilyEVM])

	ok = topology.SetNOPSignerAddress("nonexistent", chainsel.FamilyEVM, "0x456")
	assert.False(t, ok)
}
