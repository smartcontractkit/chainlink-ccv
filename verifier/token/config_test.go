package token

import (
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/lbtc"
)

func Test_Config_Deserialization(t *testing.T) {
	tomlConfig := `
verifier_id = "verifier-1"
signer_address = "0x1234567890abcdef"
pyroscope_url = "http://localhost:4040"

[on_ramp_addresses]
1 = "0xOnRamp1"
2 = "0xOnRamp2"

[rmn_remote_addresses]
"1" = "0xRMN1"
"2" = "0xRMN2"

[[token_verifiers]]
type = "cctp"
version = "2.0"
attestation_api_timeout = "11ms"
attestation_api = "https://iris-api.circle.com"

[token_verifiers.addresses]
"1" = "0xCCTPVerifier1"
2 = "0xCCTPVerifier2"

[[token_verifiers]]
type = "lbtc"
version = "1.0"
attestation_api = "https://lbtc-api.example.com"
attestation_api_timeout = "10s"
attestation_api_interval = 20

[token_verifiers.addresses]
1 = "0xLBTCVerifier1"
2 = "0xLBTCVerifier2"
`

	var config Config
	err := toml.Unmarshal([]byte(tomlConfig), &config)
	require.NoError(t, err)

	require.Len(t, config.TokenVerifiers, 2)
	cctpVerifier := config.TokenVerifiers[0]
	assert.Equal(t, "cctp", cctpVerifier.Type)
	assert.Equal(t, "2.0", cctpVerifier.Version)
	assert.Equal(t, 11*time.Millisecond, cctpVerifier.cctp.AttestationAPITimeout)
	assert.Equal(t, "https://iris-api.circle.com", cctpVerifier.cctp.AttestationAPI)
	assert.Equal(t, protocol.UnknownAddress("0xCCTPVerifier1"), cctpVerifier.cctp.Verifiers[1])
	assert.Equal(t, protocol.UnknownAddress("0xCCTPVerifier2"), cctpVerifier.cctp.Verifiers[2])

	lbtcVerifier := config.TokenVerifiers[1]
	assert.Equal(t, "lbtc", lbtcVerifier.Type)
	assert.Equal(t, "1.0", lbtcVerifier.Version)
	assert.Equal(t, 10*time.Second, lbtcVerifier.lbtc.AttestationAPITimeout)
	assert.Equal(t, 100*time.Millisecond, lbtcVerifier.lbtc.AttestationAPIInterval)
	assert.Equal(t, "https://lbtc-api.example.com", lbtcVerifier.lbtc.AttestationAPI)
	assert.Equal(t, protocol.UnknownAddress("0xLBTCVerifier1"), lbtcVerifier.lbtc.Verifiers[1])
	assert.Equal(t, protocol.UnknownAddress("0xLBTCVerifier2"), lbtcVerifier.lbtc.Verifiers[2])
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
				type = "cctp"
				version = "2.0"
				attestation_api = "http://circle.com/attestation"
				attestation_api_timeout = "100s"
				attestation_api_interval = "300ms"
				attestation_api_cooldown = "5m"
				
				[addresses]
				1 = "0xVerifier1"
				2 = "0xVerifier2"
			`,
			expected: VerifierConfig{
				Type:    "cctp",
				Version: "2.0",
				cctp: &cctp.Config{
					AttestationAPI:         "http://circle.com/attestation",
					AttestationAPITimeout:  100 * time.Second,
					AttestationAPIInterval: 300 * time.Millisecond,
					AttestationAPICooldown: 5 * time.Minute,
					Verifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
						1: protocol.UnknownAddress("0xVerifier1"),
						2: protocol.UnknownAddress("0xVerifier2"),
					},
				},
			},
		},
		{
			name: "valid cctp config with missing optional values",
			toml: `
				type = "cctp"
				version = "2.0"
				attestation_api = "http://circle.com/attestation"

				[addresses]
				"1" = "0xVerifier1"
			`,
			expected: VerifierConfig{
				Type:    "cctp",
				Version: "2.0",
				cctp: &cctp.Config{
					AttestationAPI:         "http://circle.com/attestation",
					AttestationAPITimeout:  1 * time.Second,
					AttestationAPIInterval: 100 * time.Millisecond,
					AttestationAPICooldown: 5 * time.Minute,
					Verifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
						1: protocol.UnknownAddress("0xVerifier1"),
					},
				},
			},
		},
		{
			name: "malformed cctp config returns error",
			toml: `
				type = "cctp"
				version = "2.0"
				attestation_api_timeout = "not-a-duration"

				[addresses]
				1 = "0xVerifier1"
			`,
			wantErr: true,
		},
		{
			name: "valid lbtc config with all values provided",
			toml: `
				type = "lbtc"
				version = "1.0"
				attestation_api = "http://lbtc.com/gohere"
				attestation_api_timeout = "2s"
				attestation_api_interval = "500ms"
				attestation_api_batch_size = 50

				[addresses]
				1 = "0xLBTCVerifier1"
				2 = "0xLBTCVerifier2"	
			`,
			expected: VerifierConfig{
				Type:    "lbtc",
				Version: "1.0",
				lbtc: &lbtc.Config{
					AttestationAPI:          "http://lbtc.com/gohere",
					AttestationAPITimeout:   2 * time.Second,
					AttestationAPIInterval:  500 * time.Millisecond,
					AttestationAPIBatchSize: 50,
					Verifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
						1: protocol.UnknownAddress("0xLBTCVerifier1"),
						2: protocol.UnknownAddress("0xLBTCVerifier2"),
					},
				},
			},
		},
		{
			name: "valid lbtc config with missing optional values",
			toml: `
				type = "lbtc"
				version = "1.0"
				attestation_api = "http://lbtc.com/gohere"

				[addresses]
				1 = "0xLBTCVerifier1"
			`,
			expected: VerifierConfig{
				Type:    "lbtc",
				Version: "1.0",
				lbtc: &lbtc.Config{
					AttestationAPI:          "http://lbtc.com/gohere",
					AttestationAPITimeout:   1 * time.Second,
					AttestationAPIInterval:  100 * time.Millisecond,
					AttestationAPIBatchSize: 20,
					Verifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
						1: protocol.UnknownAddress("0xLBTCVerifier1"),
					},
				},
			},
		},
		{
			name: "malformed lbtc config returns error",
			toml: `
				type = "lbtc"
				version = "1.0"
				attestation_api_dur = "10s"

				[addresses]
				1 = "0xLBTCVerifier1"
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

			if tt.expected.cctp != nil {
				require.NotNil(t, result.cctp)
				assert.Equal(t, tt.expected.cctp.AttestationAPI, result.cctp.AttestationAPI)
				assert.Equal(t, tt.expected.cctp.AttestationAPIInterval, result.cctp.AttestationAPIInterval)
				assert.Equal(t, tt.expected.cctp.AttestationAPICooldown, result.cctp.AttestationAPICooldown)
				assert.Equal(t, tt.expected.cctp.Verifiers, result.cctp.Verifiers)
			} else {
				assert.Nil(t, result.cctp)
			}

			if tt.expected.lbtc != nil {
				require.NotNil(t, result.lbtc)
				assert.Equal(t, tt.expected.lbtc.AttestationAPI, result.lbtc.AttestationAPI)
				assert.Equal(t, tt.expected.lbtc.AttestationAPITimeout, result.lbtc.AttestationAPITimeout)
				assert.Equal(t, tt.expected.lbtc.AttestationAPIInterval, result.lbtc.AttestationAPIInterval)
				assert.Equal(t, tt.expected.lbtc.AttestationAPIBatchSize, result.lbtc.AttestationAPIBatchSize)
				assert.Equal(t, tt.expected.lbtc.Verifiers, result.lbtc.Verifiers)
			} else {
				assert.Nil(t, result.lbtc)
			}
		})
	}
}
