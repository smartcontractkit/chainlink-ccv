package commit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
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

	cfg, infos, err := LoadConfigWithBlockchainInfos(tomlConfig)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotNil(t, infos)

	assert.Equal(t, "test-verifier", cfg.VerifierID)
	assert.Equal(t, "aggregator:443", cfg.AggregatorAddress)
	assert.Len(t, infos, 1)

	info, ok := infos["1"]
	require.True(t, ok, "blockchain_infos should contain key \"1\"")
	require.NotNil(t, info)

	gcfg := chainaccess.GenericConfig{ChainConfig: infos}
	var tinfo testChainInfo
	require.NoError(t, gcfg.GetConcreteConfig(protocol.ChainSelector(1), &tinfo))
	assert.Equal(t, "1", tinfo.ChainID)
	assert.Equal(t, "evm", tinfo.Type)
	assert.Equal(t, "evm", tinfo.Family)
	assert.Equal(t, "chain-1", tinfo.UniqueChainName)
}

func TestLoadConfigWithBlockchainInfos_UnknownTopLevelKey_ReturnsError(t *testing.T) {
	tomlConfig := `
typo_key = "should fail"
`
	_, _, err := LoadConfigWithBlockchainInfos(tomlConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown fields")
	assert.Contains(t, err.Error(), "typo_key")
}

func TestLoadConfigWithBlockchainInfos_UnknownKeyUnderBlockchainInfos_ReturnsError(t *testing.T) {
	tomlConfig := `
[blockchain_infos."1"]
UnknownField = "should fail"
`
	_, _, err := LoadConfigWithBlockchainInfos(tomlConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown fields")
	assert.Contains(t, err.Error(), "blockchain_infos")
}

func TestLoadConfigWithBlockchainInfos_EmptyBlockchainInfos(t *testing.T) {
	tomlConfig := ``
	cfg, infos, err := LoadConfigWithBlockchainInfos(tomlConfig)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Empty(t, infos, "blockchain_infos should be nil or empty when key is absent")
}
