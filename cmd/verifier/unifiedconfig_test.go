package verifier

import (
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/cctp"
)

const mixedUnifiedConfigTOML = `
	pyroscope_url = "http://localhost:4040"
	http_listen_port = 8101
	disable_finality_checkers = ["5009297550715157269"]

	[on_ramp_addresses]
	"5009297550715157269" = "0x0000000000000000000000000000000000000001"

	[[verifiers]]
	type = "committee"
	verifier_id = "committee-1"
	signer_address = "auto"
	message_disablement_rules_poll_interval = "2s"

	[verifiers.committee_verifier_addresses]
	"5009297550715157269" = "0x0000000000000000000000000000000000000002"

	[verifiers.default_executor_on_ramp_addresses]
	"5009297550715157269" = "0x0000000000000000000000000000000000000003"

	[[verifiers.aggregators]]
	address = "localhost:50051"
	secret_name = "agg1"
	insecure_connection = true

	[[verifiers]]
	type = "cctp"
	verifier_id = "usdc-cctp"
	version = "2.0"
	attestation_api = "https://iris-api.circle.com"
	attestation_api_timeout = "11ms"

	[verifiers.verifier_resolver_addresses]
	"1" = "0x1111111111111111111111111111111111111111"
`

func assertMixedUnifiedConfig(t *testing.T, config UnifiedConfig) {
	t.Helper()
	assert.Equal(t, "http://localhost:4040", config.PyroscopeURL)
	assert.Equal(t, 8101, config.HTTPListenPort)
	assert.Equal(t, []string{"5009297550715157269"}, config.DisableFinalityCheckers)
	assert.Equal(t, "0x0000000000000000000000000000000000000001", config.OnRampAddresses["5009297550715157269"])

	require.Len(t, config.Verifiers, 2)

	committeeEntry := config.Verifiers[0]
	assert.Equal(t, VerifierTypeCommittee, committeeEntry.Type)
	assert.Equal(t, "committee-1", committeeEntry.VerifierID)
	require.NotNil(t, committeeEntry.CommitteeEntryConfig)
	assert.Equal(t, "auto", committeeEntry.SignerAddress)
	assert.Equal(t, "2s", committeeEntry.MessageDisablementRulesPollInterval)
	assert.Equal(t, "0x0000000000000000000000000000000000000002", committeeEntry.CommitteeVerifierAddresses["5009297550715157269"])
	assert.Equal(t, "0x0000000000000000000000000000000000000003", committeeEntry.DefaultExecutorOnRampAddresses["5009297550715157269"])
	require.Len(t, committeeEntry.Aggregators, 1)
	assert.Equal(t, "localhost:50051", committeeEntry.Aggregators[0].Address)
	assert.Equal(t, "agg1", committeeEntry.Aggregators[0].SecretName)
	assert.True(t, committeeEntry.Aggregators[0].InsecureConnection)

	cctpEntry := config.Verifiers[1]
	assert.Equal(t, VerifierTypeCCTP, cctpEntry.Type)
	assert.Equal(t, "usdc-cctp", cctpEntry.VerifierID)
	assert.Equal(t, "2.0", cctpEntry.Version)
	require.NotNil(t, cctpEntry.CCTPConfig)
	assert.Equal(t, "https://iris-api.circle.com", cctpEntry.CCTPConfig.AttestationAPI)
	assert.Equal(t, 11*time.Millisecond, cctpEntry.CCTPConfig.AttestationAPITimeout)
	expectedAddr, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
	require.NoError(t, err)
	assert.Equal(t, expectedAddr, cctpEntry.CCTPConfig.ParsedVerifierResolvers[1])
}

func Test_UnifiedConfig_Deserialization(t *testing.T) {
	var config UnifiedConfig
	err := toml.Unmarshal([]byte(mixedUnifiedConfigTOML), &config)
	require.NoError(t, err)

	assertMixedUnifiedConfig(t, config)
	require.NoError(t, config.Validate())

	out, err := toml.Marshal(&config)
	require.NoError(t, err)

	var config2 UnifiedConfig
	err = toml.Unmarshal(out, &config2)
	require.NoError(t, err)

	assertMixedUnifiedConfig(t, config2)
	assert.Equal(t, config, config2)
}

func Test_UnifiedConfig_ToCommitConfig(t *testing.T) {
	var config UnifiedConfig
	require.NoError(t, toml.Unmarshal([]byte(mixedUnifiedConfigTOML), &config))

	committeeEntry := config.Verifiers[0]
	commitCfg := committeeEntry.ToCommitConfig(config)
	commitCfg.VerifierID = committeeEntry.VerifierID

	// Entry-level fields come from the entry; shared fields from the service level.
	assert.Equal(t, "auto", commitCfg.SignerAddress)
	assert.Equal(t, "http://localhost:4040", commitCfg.PyroscopeURL)
	assert.Equal(t, 8101, commitCfg.HTTPListenPort)
	assert.Equal(t, []string{"5009297550715157269"}, commitCfg.DisableFinalityCheckers)
	assert.Equal(t, config.OnRampAddresses, commitCfg.OnRampAddresses)
	require.NoError(t, commitCfg.Validate())
	resolved, err := commitCfg.ResolvedAggregators()
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	assert.Equal(t, "localhost:50051", resolved[0].Address)
}

func validUnifiedConfig() UnifiedConfig {
	return UnifiedConfig{
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses: map[string]string{"1": "0x0000000000000000000000000000000000000001"},
		},
		Verifiers: []Entry{
			{
				Type:       VerifierTypeCommittee,
				VerifierID: "committee-1",
				CommitteeEntryConfig: &CommitteeEntryConfig{
					AggregatorAddress:          "localhost:50051",
					SignerAddress:              "auto",
					CommitteeVerifierAddresses: map[string]string{"1": "0x0000000000000000000000000000000000000002"},
				},
			},
		},
	}
}

func Test_UnifiedConfig_Validate(t *testing.T) {
	t.Run("valid committee-only config", func(t *testing.T) {
		cfg := validUnifiedConfig()
		require.NoError(t, cfg.Validate())
	})

	t.Run("no entries", func(t *testing.T) {
		cfg := UnifiedConfig{}
		require.ErrorContains(t, cfg.Validate(), "at least one [[verifiers]] entry is required")
	})

	t.Run("duplicate verifier_id", func(t *testing.T) {
		cfg := validUnifiedConfig()
		cfg.Verifiers = append(cfg.Verifiers, Entry{Type: VerifierTypeCCTP, VerifierID: "committee-1", CCTPConfig: &cctp.CCTPConfig{}})
		require.ErrorContains(t, cfg.Validate(), `duplicate verifier_id "committee-1"`)
	})

	t.Run("two committee entries", func(t *testing.T) {
		cfg := validUnifiedConfig()
		second := cfg.Verifiers[0]
		second.VerifierID = "committee-2"
		cfg.Verifiers = append(cfg.Verifiers, second)
		require.ErrorContains(t, cfg.Validate(), "at most one committee entry is allowed")
	})

	t.Run("unknown type", func(t *testing.T) {
		cfg := validUnifiedConfig()
		cfg.Verifiers = []Entry{{Type: "bogus", VerifierID: "x"}}
		require.ErrorContains(t, cfg.Validate(), `unknown verifier type "bogus"`)
	})

	t.Run("mismatched onramp and committee_verifier_addresses keys", func(t *testing.T) {
		cfg := validUnifiedConfig()
		cfg.OnRampAddresses["2"] = "0x0000000000000000000000000000000000000004"
		err := cfg.Validate()
		require.Error(t, err)
		require.ErrorContains(t, err, "mismatched lengths")
	})

	t.Run("http_listen_port out of range", func(t *testing.T) {
		cfg := validUnifiedConfig()
		cfg.HTTPListenPort = 65536
		require.ErrorContains(t, cfg.Validate(), "http_listen_port must not exceed")

		cfg.HTTPListenPort = -1
		require.ErrorContains(t, cfg.Validate(), "http_listen_port must not be negative")
	})

	t.Run("committee entry without aggregator is rejected by ResolvedAggregators on startup only", func(t *testing.T) {
		cfg := validUnifiedConfig()
		cfg.Verifiers[0].AggregatorAddress = ""
		require.NoError(t, cfg.Validate())
	})
}

func Test_Entry_UnmarshalTOML(t *testing.T) {
	t.Run("unknown type is a parse error", func(t *testing.T) {
		const entryTOML = `
			verifier_id = "x"
			type = "bogus"
			version = "1.0"
		`
		var entry Entry
		err := toml.Unmarshal([]byte(entryTOML), &entry)
		require.ErrorContains(t, err, "unsupported verifier type bogus and version 1.0")
	})

	t.Run("missing verifier_id is a parse error", func(t *testing.T) {
		const entryTOML = `
			type = "committee"
		`
		var entry Entry
		err := toml.Unmarshal([]byte(entryTOML), &entry)
		require.ErrorContains(t, err, "verifier_id field is required")
	})

	t.Run("missing version for token type is a parse error", func(t *testing.T) {
		const entryTOML = `
			verifier_id = "x"
			type = "cctp"
			attestation_api = "https://iris-api.circle.com"
		`
		var entry Entry
		err := toml.Unmarshal([]byte(entryTOML), &entry)
		require.ErrorContains(t, err, "version field is required")
	})

	t.Run("lombard entry parses via lombard.TryParsing", func(t *testing.T) {
		const entryTOML = `
			verifier_id = "lbtc"
			type = "lombard"
			version = "1.0"
			attestation_api = "https://lombard-api.example.com"

			[verifier_resolver_addresses]
			1 = "0x2222222222222222222222222222222222222222"
		`
		var entry Entry
		require.NoError(t, toml.Unmarshal([]byte(entryTOML), &entry))
		assert.Equal(t, VerifierTypeLombard, entry.Type)
		require.NotNil(t, entry.LombardConfig)
		assert.Equal(t, "https://lombard-api.example.com", entry.LombardConfig.AttestationAPI)
	})
}
