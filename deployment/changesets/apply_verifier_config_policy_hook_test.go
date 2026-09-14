package changesets

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/policy"
)

// buildSpecsForPolicyHookNOP builds the verifier job specs for a single NOP carrying hook in the
// given mode.
func buildSpecsForPolicyHookNOP(t *testing.T, mode shared.NOPMode, hook *policy.Config) (shared.NOPJobSpecs, error) {
	t.Helper()
	registerEVMChainTypeForIdentities()

	specs, _, err := buildVerifierJobSpecs(
		map[string]*adapters.VerifierContractAddresses{
			"1": {
				CommitteeVerifierAddress: "0xCommittee1",
				OnRampAddress:            "0xOnRamp1",
			},
		},
		map[string]string{"1": "0xExec1"},
		nil,
		[]verifierNOPInput{{
			Alias:                 "nop1",
			SignerAddressByFamily: map[string]string{"evm": "0x47a5eed5c86da7dd9bb75488cd3832dd6782252e"},
			Mode:                  mode,
			PolicyHook:            hook,
		}},
		verifierCommitteeInput{
			Qualifier:  "default",
			NOPAliases: []shared.NOPAlias{"nop1"},
			Aggregators: []AggregatorRef{
				{Name: "agg-a", Address: "agg-a:50051", InsecureAggregatorConnection: true},
			},
		},
		"",
		nil,
		"evm",
		true,
		defaultApplyVerifierConfigApplyOverrides(),
	)
	return specs, err
}

// parseStandaloneVerifierConfig reads the config out of a standalone-mode spec, which carries it
// under appConfig rather than committeeVerifierConfig.
func parseStandaloneVerifierConfig(t *testing.T, jobSpec string) commit.Config {
	t.Helper()
	const open = "appConfig = '''\n"
	i := strings.Index(jobSpec, open)
	require.GreaterOrEqual(t, i, 0, "job spec must contain appConfig")
	rest := jobSpec[i+len(open):]
	end := strings.Index(rest, "'''")
	require.GreaterOrEqual(t, end, 0)
	var cfg commit.Config
	require.NoError(t, toml.Unmarshal([]byte(rest[:end]), &cfg))
	return cfg
}

func testPolicyHook() *policy.Config {
	return &policy.Config{BaseURL: "https://policy.internal.acme.example"}
}

// A verifier running inside a Chainlink node rejects [policy_hook] at startup, so emitting the
// section into a cl-mode spec ships a job that cannot load. The mismatch has to surface here,
// while the operator can still fix the topology, rather than as a job that fails on the node.
func TestBuildVerifierJobSpecs_RejectsPolicyHookOnCLModeNOP(t *testing.T) {
	_, err := buildSpecsForPolicyHookNOP(t, shared.NOPModeCL, testPolicyHook())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy hook is supported on a standalone verifier only")
}

// An unset mode defaults to cl, so a topology that only adds the hook is rejected the same way.
func TestBuildVerifierJobSpecs_RejectsPolicyHookOnDefaultModeNOP(t *testing.T) {
	_, err := buildSpecsForPolicyHookNOP(t, "", testPolicyHook())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy hook is supported on a standalone verifier only")
}

func TestBuildVerifierJobSpecs_EmitsPolicyHookOnStandaloneNOP(t *testing.T) {
	specs, err := buildSpecsForPolicyHookNOP(t, shared.NOPModeStandalone, testPolicyHook())
	require.NoError(t, err)

	jobs := specs["nop1"]
	require.Len(t, jobs, 1)
	for _, spec := range jobs {
		cfg := parseStandaloneVerifierConfig(t, spec)
		require.NotNil(t, cfg.PolicyHook)
		assert.Equal(t, "https://policy.internal.acme.example", cfg.PolicyHook.BaseURL)
	}
}

// A cl-mode NOP without a hook is untouched by the guard.
func TestBuildVerifierJobSpecs_CLModeWithoutPolicyHookIsUnaffected(t *testing.T) {
	specs, err := buildSpecsForPolicyHookNOP(t, shared.NOPModeCL, nil)
	require.NoError(t, err)

	jobs := specs["nop1"]
	require.Len(t, jobs, 1)
	for _, spec := range jobs {
		assert.Nil(t, parseVerifierConfig(t, spec).PolicyHook)
	}
}
