package commit

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
verifier_id = "test-verifier"
aggregator_address = "aggregator:443"
signer_address = "0x1234567890123456789012345678901234567890"
pyroscope_url = ""
committee_verifier_addresses = { "1" = "0xabc" }
on_ramp_addresses = { "1" = "0xdef" }
default_executor_on_ramp_addresses = { "1" = "0xghi" }
rmn_remote_addresses = { "1" = "0xjkl" }

[blockchain_infos."1"]
ChainID = "1"
Type = "evm"
Family = "evm"
UniqueChainName = "chain-1"
`
	spec := JobSpec{CommitteeVerifierConfig: tomlConfig}

	cfg, infos, err := LoadConfigWithBlockchainInfos[testChainInfo](spec)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotNil(t, infos)

	assert.Equal(t, "test-verifier", cfg.VerifierID)
	assert.Equal(t, "aggregator:443", cfg.AggregatorAddress)
	assert.Len(t, infos, 1)

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
verifier_id = "test-verifier"
aggregator_address = "aggregator:443"
signer_address = "0x1234567890123456789012345678901234567890"
pyroscope_url = ""
committee_verifier_addresses = { "1" = "0xabc" }
on_ramp_addresses = { "1" = "0xdef" }
default_executor_on_ramp_addresses = { "1" = "0xghi" }
rmn_remote_addresses = { "1" = "0xjkl" }

typo_key = "should fail"

[blockchain_infos."1"]
ChainID = "1"
Type = "evm"
Family = "evm"
UniqueChainName = "chain-1"
`
	spec := JobSpec{CommitteeVerifierConfig: tomlConfig}

	_, _, err := LoadConfigWithBlockchainInfos[testChainInfo](spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown fields")
	assert.Contains(t, err.Error(), "typo_key")
}

func TestLoadConfigWithBlockchainInfos_UnknownKeyUnderBlockchainInfos_ReturnsError(t *testing.T) {
	tomlConfig := `
verifier_id = "test-verifier"
aggregator_address = "aggregator:443"
signer_address = "0x1234567890123456789012345678901234567890"
pyroscope_url = ""
committee_verifier_addresses = { "1" = "0xabc" }
on_ramp_addresses = { "1" = "0xdef" }
default_executor_on_ramp_addresses = { "1" = "0xghi" }
rmn_remote_addresses = { "1" = "0xjkl" }

[blockchain_infos."1"]
ChainID = "1"
Type = "evm"
Family = "evm"
UniqueChainName = "chain-1"
UnknownField = "should fail"
`
	spec := JobSpec{CommitteeVerifierConfig: tomlConfig}

	_, _, err := LoadConfigWithBlockchainInfos[testChainInfo](spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown fields")
	assert.Contains(t, err.Error(), "blockchain_infos")
}

func TestLoadConfigWithBlockchainInfos_EmptyBlockchainInfos(t *testing.T) {
	tomlConfig := `
verifier_id = "test-verifier"
aggregator_address = "aggregator:443"
signer_address = "0x1234567890123456789012345678901234567890"
pyroscope_url = ""
committee_verifier_addresses = {}
on_ramp_addresses = {}
default_executor_on_ramp_addresses = {}
rmn_remote_addresses = {}
`
	spec := JobSpec{CommitteeVerifierConfig: tomlConfig}

	cfg, infos, err := LoadConfigWithBlockchainInfos[testChainInfo](spec)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Empty(t, infos, "blockchain_infos should be nil or empty when key is absent")
	assert.Equal(t, "test-verifier", cfg.VerifierID)
}
