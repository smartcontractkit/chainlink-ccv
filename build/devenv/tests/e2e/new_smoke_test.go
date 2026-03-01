package e2e

import (
	"testing"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/stretchr/testify/require"
)

func TestBasic(t *testing.T) {
	cfg, err := ccv.LoadOutput[ccv.Cfg](GetSmokeTestConfig())
	require.NoError(t, err)

	harness, err := tcapi.NewTestHarness(
		t.Context(),
		GetSmokeTestConfig(),
		cfg,
		chain_selectors.FamilyEVM,
	)
	require.NoError(t, err)

	chains, err := harness.Lib.Chains(t.Context())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")

	src, dest := chains[0].CCIP17, chains[1].CCIP17

	for _, tc := range tcapi.AllBasicExtraArgsV3(src, dest) {
		if tc.HavePrerequisites(t.Context(), cfg) {
			t.Run(tc.Name(), func(t *testing.T) {
				require.NoError(t, tc.Run(t.Context(), harness, cfg))
			})
		} else {
			t.Logf("Skipping %s because current environment does not have the prerequisites", tc.Name())
		}
	}
}
