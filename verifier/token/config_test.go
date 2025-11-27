package token

import (
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestConfig_HappyPathDeserialization(t *testing.T) {
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
