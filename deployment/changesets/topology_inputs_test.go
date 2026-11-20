package changesets

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

func TestNOPInputsFromTopology_executorNodeName(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "topology.toml")
	require.NoError(t, os.WriteFile(path, []byte(`indexer_address = ["http://indexer:8100"]

[[nop_topology.nops]]
alias = "nop-0"
name = "nop-0"
mode = "standalone"
executor_node_name = "executor-evm-0"

[[nop_topology.nops]]
alias = "nop-1"
name = "nop-1"
`), 0o600))

	topology, err := ccvdeployment.LoadEnvironmentTopology(path)
	require.NoError(t, err)
	nops := NOPInputsFromTopology(topology)
	require.Len(t, nops, 2)
	require.Equal(t, "executor-evm-0", nops[0].ExecutorNodeName)
	require.Equal(t, shared.NOPModeStandalone, nops[0].Mode)
	require.Empty(t, nops[1].ExecutorNodeName)

	topology.NOPTopology.NOPs[1].ExecutorNodeName = "executor-evm-0"
	require.ErrorContains(t, topology.Validate(), `NOPs "nop-0" and "nop-1" both use executor node "executor-evm-0"`)
}

func TestNOPInputsFromTopology_executorOnlyNOPDefaultsToAlias(t *testing.T) {
	t.Parallel()
	nopTopology := &ccvdeployment.NOPTopology{
		NOPs: []ccvdeployment.NOPConfig{
			{Alias: "split", Name: "split", Mode: shared.NOPModeStandalone},
			{Alias: "split-declared", Name: "split-declared", Mode: shared.NOPModeStandalone, ExecutorNodeName: "executor-evm-1"},
			{Alias: "executor-only", Name: "executor-only", Mode: shared.NOPModeStandalone},
			{Alias: "cl-executor-only", Name: "cl-executor-only", Mode: shared.NOPModeCL},
		},
		Committees: map[string]ccvdeployment.CommitteeConfig{"default": {ChainConfigs: map[string]ccvdeployment.ChainCommitteeConfig{
			"1": {NOPAliases: []string{"split", "split-declared"}},
		}}},
	}

	got := make(map[shared.NOPAlias]string)
	for _, nop := range NOPInputsFromTopology(&ccvdeployment.EnvironmentTopology{NOPTopology: nopTopology}) {
		got[nop.Alias] = nop.ExecutorNodeName
	}
	require.Equal(t, map[shared.NOPAlias]string{
		"split":            "",
		"split-declared":   "executor-evm-1",
		"executor-only":    "executor-only",
		"cl-executor-only": "",
	}, got)

	nopTopology.NOPs[1].ExecutorNodeName = "executor-only"
	nopTopology.Committees = nil
	require.ErrorContains(t, nopTopology.Validate(), `both use executor node "executor-only"`)
}

func TestCommitteeInputFromTopologyPerFamily_filtersChainConfigs(t *testing.T) {
	t.Parallel()
	committee := ccvdeployment.CommitteeConfig{
		Qualifier: "default",
		ChainConfigs: map[string]ccvdeployment.ChainCommitteeConfig{
			strconv.FormatUint(chainsel.SOLANA_DEVNET.Selector, 10):    {NOPAliases: []string{"nop1"}},
			strconv.FormatUint(chainsel.ETHEREUM_MAINNET.Selector, 10): {NOPAliases: []string{"nop2"}},
		},
	}

	sol := CommitteeInputFromTopologyPerFamily(committee, chainsel.FamilySolana)
	require.Len(t, sol.ChainConfigs, 1)
	_, ok := sol.ChainConfigs[chainsel.SOLANA_DEVNET.Selector]
	require.True(t, ok)

	evm := CommitteeInputFromTopologyPerFamily(committee, chainsel.FamilyEVM)
	require.Len(t, evm.ChainConfigs, 1)
	_, ok = evm.ChainConfigs[chainsel.ETHEREUM_MAINNET.Selector]
	require.True(t, ok)
}

func TestExecutorPoolInputFromTopology_SourceOnlyChains(t *testing.T) {
	got := ExecutorPoolInputFromTopology(ccvdeployment.ExecutorPoolConfig{
		SourceOnlyChains: []string{"9268731218649498074", strconv.FormatUint(chainsel.TEST_90000001.Selector, 10)},
	})
	require.Equal(t, []uint64{9268731218649498074, chainsel.TEST_90000001.Selector}, got.SourceOnlyChains)
}

func TestEnvironmentTopology_SourceOnlyChainAboveInt64RoundTrip(t *testing.T) {
	const sourceOnlySelector = "9268731218649498074"
	inputPath := filepath.Join(t.TempDir(), "topology.toml")
	require.NoError(t, os.WriteFile(inputPath, []byte(`
indexer_address = ["http://indexer:8100"]

[[nop_topology.nops]]
alias = "nop1"
name = "nop1"

[executor_pools.default]
source_only_chains = ["9268731218649498074"]

[executor_pools.default.chain_configs."1"]
nop_aliases = ["nop1"]
`), 0o600))

	cfg, err := ccvdeployment.LoadEnvironmentTopology(inputPath)
	require.NoError(t, err)
	require.Equal(t, []string{sourceOnlySelector}, cfg.ExecutorPools["default"].SourceOnlyChains)
	require.Equal(t, []uint64{9268731218649498074}, ExecutorPoolInputFromTopology(cfg.ExecutorPools["default"]).SourceOnlyChains)

	outputPath := filepath.Join(t.TempDir(), "written-topology.toml")
	require.NoError(t, ccvdeployment.WriteEnvironmentTopology(outputPath, *cfg))
	reloaded, err := ccvdeployment.LoadEnvironmentTopology(outputPath)
	require.NoError(t, err)
	require.Equal(t, []string{sourceOnlySelector}, reloaded.ExecutorPools["default"].SourceOnlyChains)
}

func TestExecutorPoolConfig_ValidateSourceOnlyChains(t *testing.T) {
	topology := &ccvdeployment.NOPTopology{NOPs: []ccvdeployment.NOPConfig{{Alias: "nop1", Name: "nop1"}}}
	validPool := func() ccvdeployment.ExecutorPoolConfig {
		return ccvdeployment.ExecutorPoolConfig{
			ChainConfigs: map[string]ccvdeployment.ChainExecutorPoolConfig{
				"1": {NOPAliases: []string{"nop1"}},
			},
			SourceOnlyChains: []string{"9268731218649498074"},
		}
	}
	tests := []struct {
		name            string
		mutate          func(*ccvdeployment.ExecutorPoolConfig)
		wantErrContains string
	}{
		{
			name: "invalid selector",
			mutate: func(pool *ccvdeployment.ExecutorPoolConfig) {
				pool.SourceOnlyChains = []string{"not-a-selector"}
			},
			wantErrContains: "invalid source_only_chains selector",
		},
		{
			name: "non-canonical selector",
			mutate: func(pool *ccvdeployment.ExecutorPoolConfig) {
				pool.SourceOnlyChains = []string{"01"}
			},
			wantErrContains: "canonical decimal form",
		},
		{
			name: "duplicate selector",
			mutate: func(pool *ccvdeployment.ExecutorPoolConfig) {
				pool.SourceOnlyChains = []string{"2", "2"}
			},
			wantErrContains: "duplicate source-only chain 2",
		},
		{
			name: "overlaps destination",
			mutate: func(pool *ccvdeployment.ExecutorPoolConfig) {
				pool.SourceOnlyChains = []string{"1"}
			},
			wantErrContains: "also appears in chain_configs",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pool := validPool()
			tc.mutate(&pool)
			require.ErrorContains(t, pool.Validate("default", topology), tc.wantErrContains)
		})
	}
}
