package token

import (
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/lombard"
)

func Test_Config_Deserialization(t *testing.T) {
	tomLombardConfig := `
		pyroscope_url = "http://localhost:4040"

		[on_ramp_addresses]
		1 = "0xOnRamp1"

		[rmn_remote_addresses]
		"1" = "0xRMN1"
		"2" = "0xRMN2"

		[[token_verifiers]]
		verifier_id = "cctp-verifier-1"
		type = "cctp"
		version = "2.0"
		attestation_api_timeout = "11ms"
		attestation_api = "https://iris-api.circle.com"

		[token_verifiers.verifier_resolver_addresses]
		"1" = "0x1111111111111111111111111111111111111111"
		2 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

		[[token_verifiers]]
		verifier_id = "lombard-verifier-1"
		type = "lombard"
		version = "1.0"
		attestation_api = "https://lombard-api.example.com"
		attestation_api_timeout = "10s"
		attestation_api_interval = 20

		[token_verifiers.verifier_resolver_addresses]
		1 = "0x2222222222222222222222222222222222222222"
		2 = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	`

	assertContent := func(config Config) {
		assert.Equal(t, "http://localhost:4040", config.PyroscopeURL)
		assert.Equal(t, "0xOnRamp1", config.OnRampAddresses["1"])
		assert.Equal(t, "0xRMN1", config.RMNRemoteAddresses["1"])
		assert.Equal(t, "0xRMN2", config.RMNRemoteAddresses["2"])

		require.Len(t, config.TokenVerifiers, 2)
		cctpVerifier := config.TokenVerifiers[0]
		assert.Equal(t, "cctp-verifier-1", cctpVerifier.VerifierID)
		assert.Equal(t, "cctp", cctpVerifier.Type)
		assert.Equal(t, "2.0", cctpVerifier.Version)
		assert.Equal(t, 11*time.Millisecond, cctpVerifier.CCTPConfig.AttestationAPITimeout)
		assert.Equal(t, "https://iris-api.circle.com", cctpVerifier.CCTPConfig.AttestationAPI)
		expectedAddr1, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)
		assert.Equal(t, expectedAddr1, cctpVerifier.CCTPConfig.ParsedVerifierResolvers[1])
		expectedAddr2, err := protocol.NewUnknownAddressFromHex("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		require.NoError(t, err)
		assert.Equal(t, expectedAddr2, cctpVerifier.CCTPConfig.ParsedVerifierResolvers[2])

		lombardVerifier := config.TokenVerifiers[1]
		assert.Equal(t, "lombard-verifier-1", lombardVerifier.VerifierID)
		assert.Equal(t, "lombard", lombardVerifier.Type)
		assert.Equal(t, "1.0", lombardVerifier.Version)
		assert.Equal(t, 10*time.Second, lombardVerifier.LombardConfig.AttestationAPITimeout)
		assert.Equal(t, 100*time.Millisecond, lombardVerifier.LombardConfig.AttestationAPIInterval)
		assert.Equal(t, "https://lombard-api.example.com", lombardVerifier.LombardConfig.AttestationAPI)
		expectedAddr3, err := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
		require.NoError(t, err)
		assert.Equal(t, expectedAddr3, lombardVerifier.LombardConfig.ParsedVerifierResolvers[1])
		expectedAddr4, err := protocol.NewUnknownAddressFromHex("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		require.NoError(t, err)
		assert.Equal(t, expectedAddr4, lombardVerifier.LombardConfig.ParsedVerifierResolvers[2])
	}

	var config Config
	err := toml.Unmarshal([]byte(tomLombardConfig), &config)
	require.NoError(t, err)

	assertContent(config)

	out, err := toml.Marshal(&config)
	require.NoError(t, err)

	var config2 Config
	err = toml.Unmarshal(out, &config2)
	require.NoError(t, err)

	assertContent(config2)
	assert.Equal(t, config, config2)
}

func Test_VerifierConfig_Deserialization(t *testing.T) {
	tests := []struct {
		name     string
		toml     string
		expected VerifierConfig
		wantErr  bool
	}{
		{
			name: "valid cctp config with all values provided",
			toml: `
				verifier_id = "cctp-test-1"
				type = "cctp"
				version = "2.0"
				attestation_api = "http://circle.com/attestation"
				attestation_api_timeout = "100s"
				attestation_api_interval = "300ms"
				attestation_api_cooldown = "5m"

				[verifier_resolver_addresses]
				1 = "0x1111111111111111111111111111111111111111"
				2 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			`,
			expected: func() VerifierConfig {
				addr1, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
				require.NoError(t, err)
				addr2, err := protocol.NewUnknownAddressFromHex("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
				require.NoError(t, err)
				return VerifierConfig{
					VerifierID: "cctp-test-1",
					Type:       "cctp",
					Version:    "2.0",
					CCTPConfig: &cctp.CCTPConfig{
						AttestationAPI:         "http://circle.com/attestation",
						AttestationAPITimeout:  100 * time.Second,
						AttestationAPIInterval: 300 * time.Millisecond,
						AttestationAPICooldown: 5 * time.Minute,
						ParsedVerifierResolvers: map[protocol.ChainSelector]protocol.UnknownAddress{
							1: addr1,
							2: addr2,
						},
						ParsedVerifiers: map[protocol.ChainSelector]protocol.UnknownAddress{},
					},
				}
			}(),
		},
		{
			name: "valid cctp config with missing optional values",
			toml: `
				verifier_id = "cctp-test-2"
				type = "cctp"
				version = "2.0"
				attestation_api = "http://circle.com/attestation"

				[verifier_resolver_addresses]
				"1" = "0x1111111111111111111111111111111111111111"
			`,
			expected: func() VerifierConfig {
				addr1, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
				require.NoError(t, err)
				return VerifierConfig{
					VerifierID: "cctp-test-2",
					Type:       "cctp",
					Version:    "2.0",
					CCTPConfig: &cctp.CCTPConfig{
						AttestationAPI:         "http://circle.com/attestation",
						AttestationAPITimeout:  1 * time.Second,
						AttestationAPIInterval: 100 * time.Millisecond,
						AttestationAPICooldown: 5 * time.Minute,
						ParsedVerifierResolvers: map[protocol.ChainSelector]protocol.UnknownAddress{
							1: addr1,
						},
						ParsedVerifiers: map[protocol.ChainSelector]protocol.UnknownAddress{},
					},
				}
			}(),
		},
		{
			name: "malformed cctp config returns error",
			toml: `
				verifier_id = "cctp-test-bad"
				type = "cctp"
				version = "2.0"
				attestation_api_timeout = "not-a-duration"

				[verifier_resolver_addresses]
				1 = "0x1111111111111111111111111111111111111111"
			`,
			wantErr: true,
		},
		{
			name: "valid lombard config with all values provided",
			toml: `
				verifier_id = "lombard-test-1"
				type = "lombard"
				version = "1.0"
				attestation_api = "http://lombard.com/gohere"
				attestation_api_timeout = "2s"
				attestation_api_interval = "500ms"
				attestation_api_batch_size = 50

				[verifier_resolver_addresses]
				1 = "0x2222222222222222222222222222222222222222"
				2 = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			`,
			expected: func() VerifierConfig {
				addr1, err := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
				require.NoError(t, err)
				addr2, err := protocol.NewUnknownAddressFromHex("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
				require.NoError(t, err)
				return VerifierConfig{
					VerifierID: "lombard-test-1",
					Type:       "lombard",
					Version:    "1.0",
					LombardConfig: &lombard.LombardConfig{
						AttestationAPI:          "http://lombard.com/gohere",
						AttestationAPITimeout:   2 * time.Second,
						AttestationAPIInterval:  500 * time.Millisecond,
						AttestationAPIBatchSize: 50,
						ParsedVerifierResolvers: map[protocol.ChainSelector]protocol.UnknownAddress{
							1: addr1,
							2: addr2,
						},
					},
				}
			}(),
		},
		{
			name: "valid lombard config with missing optional values",
			toml: `
				verifier_id = "lombard-test-2"
				type = "lombard"
				version = "1.0"
				attestation_api = "http://lombard.com/gohere"

				[verifier_resolver_addresses]
				1 = "0x2222222222222222222222222222222222222222"
			`,
			expected: func() VerifierConfig {
				addr1, err := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
				require.NoError(t, err)
				return VerifierConfig{
					VerifierID: "lombard-test-2",
					Type:       "lombard",
					Version:    "1.0",
					LombardConfig: &lombard.LombardConfig{
						AttestationAPI:          "http://lombard.com/gohere",
						AttestationAPITimeout:   1 * time.Second,
						AttestationAPIInterval:  100 * time.Millisecond,
						AttestationAPIBatchSize: 20,
						ParsedVerifierResolvers: map[protocol.ChainSelector]protocol.UnknownAddress{
							1: addr1,
						},
					},
				}
			}(),
		},
		{
			name: "malformed lombard config returns error",
			toml: `
				verifier_id = "lombard-test-bad"
				type = "lombard"
				version = "1.0"
				attestation_api_dur = "10s"

				[verifier_resolver_addresses]
				1 = "0x2222222222222222222222222222222222222222"
			`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result VerifierConfig
			err := toml.Unmarshal([]byte(tt.toml), &result)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected.Type, result.Type)
			assert.Equal(t, tt.expected.Version, result.Version)

			if tt.expected.CCTPConfig != nil {
				require.NotNil(t, result.CCTPConfig)
				assert.Equal(t, tt.expected.CCTPConfig.AttestationAPI, result.CCTPConfig.AttestationAPI)
				assert.Equal(t, tt.expected.CCTPConfig.AttestationAPIInterval, result.CCTPConfig.AttestationAPIInterval)
				assert.Equal(t, tt.expected.AttestationAPICooldown, result.AttestationAPICooldown)
				assert.Equal(t, tt.expected.CCTPConfig.ParsedVerifierResolvers, result.CCTPConfig.ParsedVerifierResolvers)
			} else {
				assert.Nil(t, result.CCTPConfig)
			}

			if tt.expected.LombardConfig != nil {
				require.NotNil(t, result.LombardConfig)
				assert.Equal(t, tt.expected.LombardConfig.AttestationAPI, result.LombardConfig.AttestationAPI)
				assert.Equal(t, tt.expected.LombardConfig.AttestationAPITimeout, result.LombardConfig.AttestationAPITimeout)
				assert.Equal(t, tt.expected.LombardConfig.AttestationAPIInterval, result.LombardConfig.AttestationAPIInterval)
				assert.Equal(t, tt.expected.AttestationAPIBatchSize, result.AttestationAPIBatchSize)
				assert.Equal(t, tt.expected.LombardConfig.ParsedVerifierResolvers, result.LombardConfig.ParsedVerifierResolvers)
			} else {
				assert.Nil(t, result.LombardConfig)
			}
		})
	}
}
