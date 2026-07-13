package evm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	want := Config{BlockchainInfos: chainaccess.Infos[Info]{
		"5009297550715157269": {
			ChainID:         "1",
			Type:            "ethereum",
			Family:          "evm",
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

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte("unexpected = true\n"), 0o600))

	_, err := loadConfig(path)
	require.ErrorContains(t, err, "unknown fields in config")
}

func TestCreateEVMAccessorFactoryUsesLocalConfigInsteadOfBlockchainInfos(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte("[blockchain_infos]\n"), 0o600))
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
