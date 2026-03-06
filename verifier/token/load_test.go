package token

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testChainInfo is a minimal struct used to test LoadConfigWithBlockchainInfos.
// Field names match TOML keys produced by BurntSushi/toml when marshaling (no toml tags).
type testChainInfo struct {
	ChainID         string
	Type            string
	Family          string
	UniqueChainName string
}

func TestLoadConfigWithBlockchainInfos_Success(t *testing.T) {
	// Minimal valid config TOML with one entry in blockchain_infos
	tomlConfig := `
pyroscope_url = ""
on_ramp_addresses = { "1" = "0xdef" }
rmn_remote_addresses = { "1" = "0xjkl" }

[[token_verifiers]]
verifier_id = "cctp-verifier"
type = "cctp"
version = "2.0"
attestation_api = "http://circle.com/attestation"
attestation_api_timeout = "1s"
attestation_api_interval = "111ms"

[[token_verifiers]]
verifier_id = "lombard-verifier"
type = "lombard"
version = "1.0"
attestation_api = "http://lombard.com/attestation"
attestation_api_timeout = "2s"
attestation_api_interval = "222ms"

[blockchain_infos."1"]
ChainID = "1"
Type = "evm"
Family = "evm"
UniqueChainName = "chain-1"
`
	spec := JobSpec{TokenVerifierConfig: tomlConfig}

	cfg, infos, err := LoadConfigWithBlockchainInfos[testChainInfo](spec)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotNil(t, infos)

	assert.Len(t, cfg.TokenVerifiers, 2)
	for _, v := range cfg.TokenVerifiers {
		switch v.Type {
		case "cctp":
			assert.Equal(t, "cctp-verifier", v.VerifierID)
			assert.Equal(t, "2.0", v.Version)
			assert.NotNil(t, v.CCTPConfig)
			assert.Equal(t, "http://circle.com/attestation", v.CCTPConfig.AttestationAPI)
			assert.Equal(t, 1, int(v.CCTPConfig.AttestationAPITimeout.Seconds()))
			assert.Equal(t, 111, int(v.CCTPConfig.AttestationAPIInterval.Milliseconds()))
		case "lombard":
			assert.Equal(t, "lombard-verifier", v.VerifierID)
			assert.Equal(t, "1.0", v.Version)
			assert.NotNil(t, v.LombardConfig)
			assert.Equal(t, "http://lombard.com/attestation", v.LombardConfig.AttestationAPI)
			assert.Equal(t, 2, int(v.LombardConfig.AttestationAPITimeout.Seconds()))
			assert.Equal(t, 222, int(v.LombardConfig.AttestationAPIInterval.Milliseconds()))
		default:
			t.Errorf("unexpected verifier type: %s", v.Type)
		}
	}

	info, ok := infos["1"]
	require.True(t, ok, "blockchain_infos should contain key \"1\"")
	require.NotNil(t, info)
	assert.Equal(t, "1", info.ChainID)
	assert.Equal(t, "evm", info.Type)
	assert.Equal(t, "evm", info.Family)
	assert.Equal(t, "chain-1", info.UniqueChainName)
}

func TestLoadConfigWithBlockchainInfos_UnknownTopLevelKey_ReturnsError(t *testing.T) {
	tomlConfig := `
typo_key = "should fail"
`
	spec := JobSpec{TokenVerifierConfig: tomlConfig}

	_, _, err := LoadConfigWithBlockchainInfos[testChainInfo](spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown fields")
	assert.Contains(t, err.Error(), "typo_key")
}

func TestLoadConfigWithBlockchainInfos_UnknownKeyUnderBlockchainInfos_ReturnsError(t *testing.T) {
	tomlConfig := `
[blockchain_infos."1"]
UnknownField = "should fail"
`
	spec := JobSpec{TokenVerifierConfig: tomlConfig}

	_, _, err := LoadConfigWithBlockchainInfos[testChainInfo](spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown fields")
	assert.Contains(t, err.Error(), "blockchain_infos")
}

func TestLoadConfigWithBlockchainInfos_EmptyBlockchainInfos(t *testing.T) {
	tomlConfig := ``
	spec := JobSpec{TokenVerifierConfig: tomlConfig}

	cfg, infos, err := LoadConfigWithBlockchainInfos[testChainInfo](spec)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Empty(t, infos, "blockchain_infos should be nil or empty when key is absent")
}
