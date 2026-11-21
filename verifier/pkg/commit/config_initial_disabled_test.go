package commit

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func initialDisabledTestConfig(selectors ...string) Config {
	return Config{
		InitialDisabledChainSelectors: selectors,
		CommitteeVerifierAddresses: map[string]string{
			"1": "0xCommittee1",
			"2": "0xCommittee2",
		},
		CommitteeConfig: chainaccess.CommitteeConfig{OnRampAddresses: map[string]string{
			"1": "0xOnRamp1",
			"2": "0xOnRamp2",
		}},
	}
}

func TestConfig_InitialDisabledChainSelectors(t *testing.T) {
	t.Run("valid selectors", func(t *testing.T) {
		cfg := initialDisabledTestConfig("2", "1")
		require.NoError(t, cfg.Validate())
		selectors, err := cfg.ParseInitialDisabledChainSelectors()
		require.NoError(t, err)
		require.Equal(t, []protocol.ChainSelector{2, 1}, selectors)
	})

	for _, tc := range []struct {
		name      string
		selectors []string
		wantError string
	}{
		{name: "not a number", selectors: []string{"bad"}, wantError: "invalid initial_disabled_chain_selectors"},
		{name: "non canonical", selectors: []string{"01"}, wantError: "canonical decimal form"},
		{name: "duplicate", selectors: []string{"1", "1"}, wantError: "duplicate initial disabled"},
		{name: "not assigned", selectors: []string{"3"}, wantError: "not an assigned source chain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := initialDisabledTestConfig(tc.selectors...)
			require.ErrorContains(t, cfg.Validate(), tc.wantError)
		})
	}
}

func TestConfig_InitialDisabledChainSelectorsOmittedWhenEmpty(t *testing.T) {
	empty, err := toml.Marshal(Config{})
	require.NoError(t, err)
	require.NotContains(t, string(empty), "initial_disabled_chain_selectors")

	configured, err := toml.Marshal(Config{InitialDisabledChainSelectors: []string{"1"}})
	require.NoError(t, err)
	require.Contains(t, string(configured), `initial_disabled_chain_selectors = ["1"]`)
}
