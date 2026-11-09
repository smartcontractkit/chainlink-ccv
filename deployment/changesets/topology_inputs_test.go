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
