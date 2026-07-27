package evm

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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
			FinalityDepth: 42,
			TXMBlockTime:  12 * time.Second,
			Nodes: []Node{{
				Name:            "chainstack",
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

// The mounted config carries only operator-owned connection and runtime settings;
// the accessor derives each chain's metadata from its selector at load time.
func TestConfigToInfosDerivesChainMetadataFromSelector(t *testing.T) {
	// 5009297550715157269 is Ethereum mainnet (chain ID 1) in chain-selectors.
	cfg := Config{Chains: map[string]ChainConfig{
		"5009297550715157269": {
			FinalityDepth: 20,
			TXMBlockTime:  4 * time.Second,
			Nodes: []Node{{
				Name:            "simplyvc",
				InternalHTTPUrl: "http://evm-node:8545",
			}},
		},
	}}

	infos, err := cfg.toInfos()
	require.NoError(t, err)

	info := infos["5009297550715157269"]
	require.Equal(t, "1", info.ChainID)
	require.Equal(t, chainsel.FamilyEVM, info.Family)
	require.Empty(t, info.Type)
	require.Equal(t, uint32(20), info.FinalityDepth)
	require.Equal(t, 4*time.Second, info.TXMBlockTime)
	require.Equal(t, "simplyvc", info.Nodes[0].Name)
	require.Equal(t, "http://evm-node:8545", info.Nodes[0].InternalHTTPUrl)
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte("unexpected = true\n"), 0o600))

	_, err := loadConfig(path)
	require.ErrorContains(t, err, "unknown fields in config")
}

func TestLoadConfigRejectsDerivedChainMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[chains.5009297550715157269]
chain_type = "ethereum"
unique_chain_name = "ethereum-mainnet"
`), 0o600))

	_, err := loadConfig(path)
	require.ErrorContains(t, err, "unknown fields in config")
	require.ErrorContains(t, err, "chain_type")
	require.ErrorContains(t, err, "unique_chain_name")
}

func TestLoadConfigRejectsUnexposedChainlinkEVMNodeFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[chains.5009297550715157269]
[[chains.5009297550715157269.nodes]]
internal_http_url = "http://evm-node:8545"
SendOnly = true
`), 0o600))

	_, err := loadConfig(path)
	require.ErrorContains(t, err, "unknown fields in config")
	require.ErrorContains(t, err, "SendOnly")
}

func TestResolveConfigPath(t *testing.T) {
	t.Run("configured path", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "evm.toml")
		t.Setenv(EVMConfigPathEnv, path)

		require.Equal(t, path, resolveConfigPath())
	})

	t.Run("empty path uses default", func(t *testing.T) {
		t.Setenv(EVMConfigPathEnv, "")

		require.Equal(t, DefaultEVMConfigPath, resolveConfigPath())
	})
}

func TestCreateEVMAccessorFactoryUsesLocalConfigInsteadOfBlockchainInfos(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte("[chains]\n"), 0o600))
	t.Setenv(EVMConfigPathEnv, path)

	genericConfig := chainaccess.GenericConfig{}
	factory, err := CreateEVMAccessorFactory(logger.Test(t), genericConfig)
	require.NoError(t, err)
	require.NotNil(t, factory)
}

func TestCreateAccessorFactoryDoesNotDialRPCDuringConstruction(t *testing.T) {
	t.Parallel()

	infos := chainaccess.Infos[Info]{
		"5009297550715157269": {
			ChainID: "1",
			Family:  chainsel.FamilyEVM,
			Nodes: []Node{{
				InternalHTTPUrl: "http://127.0.0.1:1",
			}},
		},
	}

	factory, err := CreateAccessorFactory(logger.Test(t), chainaccess.GenericConfig{}, infos)
	require.NoError(t, err)
	require.NotNil(t, factory)
}
