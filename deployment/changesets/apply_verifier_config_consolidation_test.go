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
)

func buildVerifierSpecsForTest(t *testing.T, consolidate bool) shared.NOPJobSpecs {
	t.Helper()

	contractAddresses := map[string]*adapters.VerifierContractAddresses{
		"1": {
			CommitteeVerifierAddress: "0xCommittee1",
			OnRampAddress:            "0xOnRamp1",
			ExecutorProxyAddress:     "0xExec1",
			RMNRemoteAddress:         "0xRMN1",
		},
	}
	nops := []verifierNOPInput{{
		Alias:                 "nop1",
		SignerAddressByFamily: map[string]string{"evm": "0xSIGNER"},
	}}
	committee := verifierCommitteeInput{
		Qualifier: "default",
		Aggregators: []AggregatorRef{
			{Name: "agg-a", Address: "agg-a:50051", InsecureAggregatorConnection: true},
			{Name: "agg-b", Address: "agg-b:50051"},
		},
		NOPAliases: []shared.NOPAlias{"nop1"},
	}

	specs, _, err := buildVerifierJobSpecs(
		contractAddresses,
		nil,
		nops,
		committee,
		"",
		nil,
		"evm",
		consolidate,
	)
	require.NoError(t, err)
	return specs
}

func parseVerifierConfig(t *testing.T, jobSpec string) commit.Config {
	t.Helper()
	const open = "committeeVerifierConfig = '''\n"
	i := strings.Index(jobSpec, open)
	require.GreaterOrEqual(t, i, 0, "job spec must contain committeeVerifierConfig")
	rest := jobSpec[i+len(open):]
	end := strings.Index(rest, "'''")
	require.GreaterOrEqual(t, end, 0)
	var cfg commit.Config
	require.NoError(t, toml.Unmarshal([]byte(rest[:end]), &cfg))
	return cfg
}

func TestBuildVerifierJobSpecs_LegacyEmitsOneJobPerAggregator(t *testing.T) {
	specs := buildVerifierSpecsForTest(t, false)

	jobs := specs["nop1"]
	require.Len(t, jobs, 2, "legacy topology emits one job per aggregator")

	byAggregator := map[string]commit.Config{}
	for _, spec := range jobs {
		parsed := parseVerifierConfig(t, spec)
		require.Empty(t, parsed.Aggregators, "legacy jobs must not use the aggregators list")
		require.NotEmpty(t, parsed.AggregatorAddress, "legacy jobs carry a single aggregator_address")
		byAggregator[parsed.AggregatorAddress] = parsed
	}
	require.Contains(t, byAggregator, "agg-a:50051")
	require.Contains(t, byAggregator, "agg-b:50051")
	assert.True(t, byAggregator["agg-a:50051"].InsecureAggregatorConnection)
	assert.False(t, byAggregator["agg-b:50051"].InsecureAggregatorConnection)

	// Verifier IDs keep the aggregator name (legacy identity).
	assert.Contains(t, jobs, shared.NewVerifierJobID("nop1", "agg-a", shared.VerifierJobScope{CommitteeQualifier: "default"}).ToJobID())
	assert.Contains(t, jobs, shared.NewVerifierJobID("nop1", "agg-b", shared.VerifierJobScope{CommitteeQualifier: "default"}).ToJobID())
}

func TestBuildVerifierJobSpecs_ConsolidatedEmitsOneJobWithAllAggregators(t *testing.T) {
	specs := buildVerifierSpecsForTest(t, true)

	jobs := specs["nop1"]
	require.Len(t, jobs, 1, "consolidated topology emits a single job per NOP")

	consolidatedID := shared.NewConsolidatedVerifierJobID("nop1", shared.VerifierJobScope{CommitteeQualifier: "default"})
	spec, ok := jobs[consolidatedID.ToJobID()]
	require.True(t, ok, "consolidated job id must be present")

	cfg := parseVerifierConfig(t, spec)
	assert.Empty(t, cfg.AggregatorAddress, "consolidated job must not set the legacy aggregator_address")
	require.Len(t, cfg.Aggregators, 2)
	assert.Equal(t, "agg-a", cfg.Aggregators[0].Name)
	assert.Equal(t, "agg-a:50051", cfg.Aggregators[0].Address)
	assert.True(t, cfg.Aggregators[0].InsecureConnection)
	assert.Equal(t, "agg-b:50051", cfg.Aggregators[1].Address)
	assert.False(t, cfg.Aggregators[1].InsecureConnection)

	// SecretName reuses the legacy per-aggregator verifier_id so existing operator secrets keep
	// working without re-provisioning.
	assert.Equal(t, "agg-a-default-verifier", cfg.Aggregators[0].SecretName)
	assert.Equal(t, "agg-b-default-verifier", cfg.Aggregators[1].SecretName)

	// Verifier ID omits the aggregator name.
	assert.Equal(t, "default-verifier", cfg.VerifierID)
}
