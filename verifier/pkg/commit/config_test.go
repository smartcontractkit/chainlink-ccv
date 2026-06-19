package commit

import (
	"testing"
	"time"

	burntsushi "github.com/BurntSushi/toml"
	pelletier "github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

func TestConfig_Validate_Success(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "single chain",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
					},
				},
			},
		},
		{
			name: "multiple chains",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
					"2": "0xCommittee2",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
						"2": "0xOnRamp2",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
						"2": "0xRMNRemote2",
					},
				},
			},
		},
		{
			name: "empty maps",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses:    map[string]string{},
					RMNRemoteAddresses: map[string]string{},
				},
			},
		},
		{
			name: "message disablement duration strings",
			config: Config{
				MessageDisablementRulesPollInterval:  "2s",
				MessageDisablementRulesClientTimeout: "5s",
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			require.NoError(t, err)
			if tt.name == "message disablement duration strings" {
				poll, err := tt.config.MessageDisablementRulesPollIntervalDuration()
				require.NoError(t, err)
				assert.Equal(t, 2*time.Second, poll)
				timeout, err := tt.config.MessageDisablementRulesClientTimeoutDuration()
				require.NoError(t, err)
				assert.Equal(t, 5*time.Second, timeout)
			}
		})
	}
}

func TestConfig_Validate_Errors(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		errSubstr string
	}{
		{
			name: "onramp and committee length mismatch",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
						"2": "0xOnRamp2",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
						"2": "0xRMNRemote2",
					},
				},
			},
			errSubstr: "mismatched lengths",
		},
		{
			name: "onramp and RMN Remote length mismatch",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
					"2": "0xCommittee2",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
						"2": "0xOnRamp2",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
					},
				},
			},
			errSubstr: "mismatched lengths",
		},
		{
			name: "all three maps length mismatch",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
						"2": "0xOnRamp2",
						"3": "0xOnRamp3",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
						"2": "0xRMNRemote2",
					},
				},
			},
			errSubstr: "mismatched lengths",
		},
		{
			name: "onramp key absent from committee verifier addresses",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{
					"2": "0xCommittee2",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
					},
				},
			},
			errSubstr: "not in committee verifier addresses",
		},
		{
			name: "onramp key absent from RMN Remote addresses",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
					},
					RMNRemoteAddresses: map[string]string{
						"2": "0xRMNRemote2",
					},
				},
			},
			errSubstr: "not in RMN Remote addresses",
		},
		{
			name: "invalid message_disablement_rules_poll_interval",
			config: Config{
				MessageDisablementRulesPollInterval: "not-a-duration",
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
					},
				},
			},
			errSubstr: "invalid message_disablement_rules_poll_interval",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errSubstr)
		})
	}
}

func TestConfig_ResolvedAggregators(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		want      []AggregatorConnection
		errSubstr string
	}{
		{
			name:      "neither set is an error",
			config:    Config{},
			errSubstr: "no aggregator configured",
		},
		{
			name: "both set is an error",
			config: Config{
				AggregatorAddress: "legacy:50051",
				Aggregators:       []AggregatorConnection{{Address: "a:50051"}},
			},
			errSubstr: "both aggregator_address and aggregators are set",
		},
		{
			name: "legacy single address synthesizes one nameless connection",
			config: Config{
				AggregatorAddress:             "legacy:50051",
				InsecureAggregatorConnection:  true,
				AggregatorMaxSendMsgSizeBytes: 111,
				AggregatorMaxRecvMsgSizeBytes: 222,
			},
			// Name stays empty so it falls back to the default credential env vars.
			want: []AggregatorConnection{{
				Address:             "legacy:50051",
				InsecureConnection:  true,
				MaxSendMsgSizeBytes: 111,
				MaxRecvMsgSizeBytes: 222,
			}},
		},
		{
			name: "single-entry list may be nameless",
			config: Config{
				Aggregators: []AggregatorConnection{{Address: "a:50051", InsecureConnection: true}},
			},
			want: []AggregatorConnection{{Address: "a:50051", InsecureConnection: true}},
		},
		{
			name: "multi-aggregator list preserves entries verbatim",
			config: Config{
				Aggregators: []AggregatorConnection{
					{Name: "primary", SecretName: "agg-1", Address: "a:50051", InsecureConnection: true},
					{Name: "secondary", SecretName: "agg-2", Address: "b:50051"},
				},
			},
			want: []AggregatorConnection{
				{Name: "primary", SecretName: "agg-1", Address: "a:50051", InsecureConnection: true},
				{Name: "secondary", SecretName: "agg-2", Address: "b:50051"},
			},
		},
		{
			name: "multiple aggregators require secret_name",
			config: Config{
				Aggregators: []AggregatorConnection{
					{Name: "primary", SecretName: "agg-1", Address: "a:50051"},
					{Name: "secondary", Address: "b:50051"},
				},
			},
			errSubstr: "must have a secret_name when multiple aggregators",
		},
		{
			name: "duplicate aggregator secret_names are rejected",
			config: Config{
				Aggregators: []AggregatorConnection{
					{Name: "primary", SecretName: "dup", Address: "a:50051"},
					{Name: "secondary", SecretName: "dup", Address: "b:50051"},
				},
			},
			errSubstr: "duplicate aggregator secret_name",
		},
		{
			name: "duplicate addresses are rejected",
			config: Config{
				Aggregators: []AggregatorConnection{
					{Name: "primary", SecretName: "agg-1", Address: "a:50051"},
					{Name: "secondary", SecretName: "agg-2", Address: "a:50051"},
				},
			},
			errSubstr: "duplicate aggregator address",
		},
		{
			name: "empty address in list is rejected",
			config: Config{
				Aggregators: []AggregatorConnection{{Name: "noaddr"}},
			},
			errSubstr: "empty address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.config.ResolvedAggregators()
			if tt.errSubstr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAggregatorCredentialEnvVars(t *testing.T) {
	tests := []struct {
		name       string
		secretName string
		wantAPIKey string
		wantSecret string
	}{
		{"empty secret_name falls back to defaults", "", "VERIFIER_AGGREGATOR_API_KEY", "VERIFIER_AGGREGATOR_SECRET_KEY"},
		{"simple secret_name", "primary", "VERIFIER_AGGREGATOR_PRIMARY_API_KEY", "VERIFIER_AGGREGATOR_PRIMARY_SECRET_KEY"},
		{"hyphenated secret_name is sanitized", "default-aggregator", "VERIFIER_AGGREGATOR_DEFAULT_AGGREGATOR_API_KEY", "VERIFIER_AGGREGATOR_DEFAULT_AGGREGATOR_SECRET_KEY"},
		{"mixed punctuation is sanitized", "agg.1-ha", "VERIFIER_AGGREGATOR_AGG_1_HA_API_KEY", "VERIFIER_AGGREGATOR_AGG_1_HA_SECRET_KEY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, secret := AggregatorCredentialEnvVars(tt.secretName)
			assert.Equal(t, tt.wantAPIKey, apiKey)
			assert.Equal(t, tt.wantSecret, secret)
			// Method form delegates to the package function, keyed on SecretName.
			mAPIKey, mSecret := AggregatorConnection{SecretName: tt.secretName}.AggregatorCredentialEnvVars()
			assert.Equal(t, tt.wantAPIKey, mAPIKey)
			assert.Equal(t, tt.wantSecret, mSecret)
		})
	}
}

// TestConfig_AggregatorsTOMLRoundTrip guards the design risk that the aggregators
// array-of-tables must decode cleanly under BOTH TOML libraries used in this repo:
// BurntSushi/toml (standalone / devenv / changeset marshal) and pelletier/go-toml
// (Chainlink node job-spec decoding).
func TestConfig_AggregatorsTOMLRoundTrip(t *testing.T) {
	const tomlDoc = `
verifier_id = "v1"

[[aggregators]]
name = "primary"
address = "a:50051"
insecure_connection = true
max_send_msg_size_bytes = 1048576

[[aggregators]]
address = "b:50051"
`
	want := []AggregatorConnection{
		{Name: "primary", Address: "a:50051", InsecureConnection: true, MaxSendMsgSizeBytes: 1048576},
		{Address: "b:50051"},
	}

	t.Run("BurntSushi", func(t *testing.T) {
		var c Config
		require.NoError(t, burntsushi.Unmarshal([]byte(tomlDoc), &c))
		assert.Equal(t, want, c.Aggregators)
	})

	t.Run("pelletier", func(t *testing.T) {
		var c Config
		require.NoError(t, pelletier.Unmarshal([]byte(tomlDoc), &c))
		assert.Equal(t, want, c.Aggregators)
	})

	t.Run("BurntSushi marshal round-trips", func(t *testing.T) {
		c := Config{VerifierID: "v1", Aggregators: want}
		b, err := burntsushi.Marshal(c)
		require.NoError(t, err)
		var back Config
		require.NoError(t, burntsushi.Unmarshal(b, &back))
		assert.Equal(t, want, back.Aggregators)
	})
}
