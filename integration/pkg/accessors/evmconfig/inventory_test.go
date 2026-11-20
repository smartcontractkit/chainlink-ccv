package evmconfig

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	inventoryEthereumSelector = "5009297550715157269"
	inventoryPolygonSelector  = "4051577828743386545"
)

func inventoryConfig(chainIDs ...string) *Config {
	chains := make(map[string]ChainConfig, len(chainIDs))
	for _, chainID := range chainIDs {
		switch chainID {
		case "1":
			chains[inventoryEthereumSelector] = ChainConfig{}
		case "137":
			chains[inventoryPolygonSelector] = ChainConfig{}
		}
	}
	return &Config{Chains: chains}
}

func TestReconcileChainInventory(t *testing.T) {
	t.Run("valid with an explicitly disabled chain", func(t *testing.T) {
		report, err := ReconcileChainInventory(inventoryConfig("1"), &Conversion{DisabledChains: []string{"137"}}, []ChainDeclaration{
			{Type: "EVM", ID: "1"}, {Type: "evm", ID: "137"},
		})
		require.NoError(t, err)
		require.NoError(t, report.Err())
		require.Equal(t, []string{"1", "137"}, report.ConfiguredChains)
		require.Equal(t, []string{"1", "137"}, report.DeclaredChains)
	})

	t.Run("empty", func(t *testing.T) {
		report, err := ReconcileChainInventory(inventoryConfig("1"), nil, nil)
		require.NoError(t, err)
		require.True(t, report.Empty)
		require.ErrorContains(t, report.Err(), "at least one EVM chain")
		require.Equal(t, []string{"1"}, report.MissingDeclarations)
	})

	t.Run("missing and extra declarations name their chains", func(t *testing.T) {
		report, err := ReconcileChainInventory(inventoryConfig("1", "137"), nil, []ChainDeclaration{{Type: "EVM", ID: "1"}})
		require.NoError(t, err)
		require.Equal(t, []string{"137"}, report.MissingDeclarations)
		require.ErrorContains(t, report.Err(), "137")

		report, err = ReconcileChainInventory(inventoryConfig("1"), nil, []ChainDeclaration{
			{Type: "EVM", ID: "1"}, {Type: "EVM", ID: "137"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{"137"}, report.ExtraDeclarations)
		require.ErrorContains(t, report.Err(), "137")
	})

	t.Run("duplicate declaration", func(t *testing.T) {
		report, err := ReconcileChainInventory(inventoryConfig("1"), nil, []ChainDeclaration{
			{Type: "EVM", ID: "1"}, {Type: "EVM", ID: "1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{"1"}, report.DuplicateDeclarations)
		require.ErrorContains(t, report.Err(), "duplicate")
	})

	t.Run("unsupported declarations", func(t *testing.T) {
		report, err := ReconcileChainInventory(inventoryConfig("1"), nil, []ChainDeclaration{
			{Type: "EVM", ID: "1"},
			{Type: "SOLANA", ID: "1"},
			{Type: "EVM", ID: "88888888888888"},
		})
		require.NoError(t, err)
		require.Len(t, report.UnsupportedDeclarations, 2)
		require.ErrorContains(t, report.Err(), "SOLANA/1")
		require.ErrorContains(t, report.Err(), "EVM/88888888888888")
	})

	t.Run("failed conversion is unsupported rather than extra", func(t *testing.T) {
		conversion := &Conversion{FailedChains: []ChainFailure{{ChainID: "137", Reason: "no HTTPURL"}}}
		report, err := ReconcileChainInventory(inventoryConfig("1"), conversion, []ChainDeclaration{
			{Type: "EVM", ID: "1"}, {Type: "EVM", ID: "137"},
		})
		require.NoError(t, err)
		require.Empty(t, report.ExtraDeclarations)
		require.ErrorContains(t, report.Err(), "EVM/137")
		require.ErrorContains(t, report.Err(), "no HTTPURL")
	})
}
