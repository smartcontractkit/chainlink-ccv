package changesets

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
)

func buildInitialDisabledJobSpec(mode shared.NOPMode, selectors []string) (string, error) {
	addresses := map[string]*adapters.VerifierContractAddresses{
		"1": {CommitteeVerifierAddress: "0xCommittee1", OnRampAddress: "0xOnRamp1"},
		"2": {CommitteeVerifierAddress: "0xCommittee2", OnRampAddress: "0xOnRamp2"},
	}
	specs, _, err := buildVerifierJobSpecs(
		addresses,
		map[string]string{"1": "0xExec1", "2": "0xExec2"},
		nil,
		[]verifierNOPInput{{
			Alias:                         "nop1",
			SignerAddressByFamily:         map[string]string{"evm": "0xSIGNER"},
			Mode:                          mode,
			InitialDisabledChainSelectors: selectors,
		}},
		verifierCommitteeInput{
			Qualifier:       "default",
			Aggregators:     []AggregatorRef{{Name: "agg", Address: "agg:50051"}},
			NOPAliases:      []shared.NOPAlias{"nop1"},
			ChainNOPAliases: map[string][]shared.NOPAlias{"1": {"nop1"}, "2": {"nop1"}},
		},
		"", nil, "evm", true, defaultApplyVerifierConfigApplyOverrides(),
	)
	if err != nil {
		return "", err
	}
	for _, spec := range specs["nop1"] {
		return spec, nil
	}
	return "", nil
}

func parseStandaloneInitialDisabledConfig(t *testing.T, spec string) commit.Config {
	t.Helper()
	const open = "appConfig = '''\n"
	start := strings.Index(spec, open)
	require.GreaterOrEqual(t, start, 0)
	rest := spec[start+len(open):]
	end := strings.Index(rest, "'''")
	require.GreaterOrEqual(t, end, 0)
	var cfg commit.Config
	require.NoError(t, toml.Unmarshal([]byte(rest[:end]), &cfg))
	return cfg
}

func TestBuildVerifierJobSpecs_InitialDisabledChains(t *testing.T) {
	spec, err := buildInitialDisabledJobSpec(shared.NOPModeStandalone, []string{"2", "1"})
	require.NoError(t, err)
	cfg := parseStandaloneInitialDisabledConfig(t, spec)
	require.Equal(t, []string{"1", "2"}, cfg.InitialDisabledChainSelectors)
}

func TestBuildVerifierJobSpecs_InitialDisabledChainsOmittedByDefault(t *testing.T) {
	spec, err := buildInitialDisabledJobSpec(shared.NOPModeStandalone, nil)
	require.NoError(t, err)
	require.NotContains(t, spec, "initial_disabled_chain_selectors")
}

func TestBuildVerifierJobSpecs_InitialDisabledChainsRejectedForCL(t *testing.T) {
	spec, err := buildInitialDisabledJobSpec(shared.NOPModeCL, []string{"1"})
	require.ErrorContains(t, err, "seeding is supported on a standalone verifier only")
	require.Empty(t, spec)
}

func TestBuildVerifierJobSpecs_InitialDisabledChainsValidated(t *testing.T) {
	for _, tc := range []struct {
		name      string
		selector  string
		wantError string
	}{
		{name: "non canonical", selector: "01", wantError: "canonical decimal form"},
		{name: "unassigned", selector: "3", wantError: "not an assigned source chain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := buildInitialDisabledJobSpec(shared.NOPModeStandalone, []string{tc.selector})
			require.ErrorContains(t, err, tc.wantError)
			require.Empty(t, spec)
		})
	}
}
