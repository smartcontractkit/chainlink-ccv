package evm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	want := Config{Chains: map[string]ChainConfig{
		"5009297550715157269": {
			ChainType:       "ethereum",
			UniqueChainName: "ethereum-mainnet",
			Nodes: []Node{{
				InternalHTTPUrl: "http://evm-node:8545",
				InternalWSUrl:   "ws://evm-node:8546",
			}},
		},
	}}

	data, err := toml.Marshal(want)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	got, err := loadConfig(path)
	require.NoError(t, err)
	require.Equal(t, want, *got)
}

// The mounted config carries only connection and tuning settings; the accessor derives each
// chain's ID and family from its selector at load time.
func TestConfigToInfosDerivesChainMetadataFromSelector(t *testing.T) {
	// 5009297550715157269 is Ethereum mainnet (chain ID 1) in chain-selectors.
	cfg := Config{Chains: map[string]ChainConfig{
		"5009297550715157269": {
			ChainType: "ethereum",
			Nodes:     []Node{{InternalHTTPUrl: "http://evm-node:8545"}},
		},
	}}

	infos, err := cfg.toInfos()
	require.NoError(t, err)

	info := infos["5009297550715157269"]
	require.Equal(t, "1", info.ChainID)
	require.Equal(t, chainsel.FamilyEVM, info.Family)
	require.Equal(t, "ethereum", info.Type)
	require.Equal(t, "http://evm-node:8545", info.Nodes[0].InternalHTTPUrl)
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte("unexpected = true\n"), 0o600))

	_, err := loadConfig(path)
	require.ErrorContains(t, err, "unknown fields in config")
}

func TestCreateEVMAccessorFactoryUsesLocalConfigInsteadOfBlockchainInfos(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte("[chains]\n"), 0o600))
	t.Setenv(EVMConfigPathEnv, path)

	genericConfig := chainaccess.GenericConfig{ //nolint:staticcheck // SA1019: constructor API still accepts shared GenericConfig
		ChainConfig: chainaccess.Infos[any]{
			"5009297550715157269": map[string]any{"must_not_be_decoded": true},
		},
	}
	factory, err := CreateEVMAccessorFactory(logger.Test(t), genericConfig)
	require.NoError(t, err)
	require.NotNil(t, factory)
}
