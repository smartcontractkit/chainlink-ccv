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
				Name:    "chainstack",
				HTTPUrl: "http://evm-node:8545",
				WSUrl:   "ws://evm-node:8546",
			}},
		},
	}}

	data, err := toml.Marshal(want)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	got, _, err := loadConfig(path)
	require.NoError(t, err)
	require.Equal(t, want, *got)
}

// The CTF-shaped endpoint split is not part of the operator surface: a file still carrying it must
// fail loudly rather than start with no RPC configured.
func TestLoadConfigRejectsCTFInternalExternalNodeURLs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[chains.5009297550715157269]
[[chains.5009297550715157269.nodes]]
internal_http_url = "http://evm-node:8545"
external_ws_url = "wss://eth-mainnet.example.com"
`), 0o600))

	_, _, err := loadConfig(path)
	require.ErrorContains(t, err, "unknown fields in config")
	require.ErrorContains(t, err, "internal_http_url")
	require.ErrorContains(t, err, "external_ws_url")
}

// A node config that converts cleanly produces no warnings, so the warning count cannot be used to
// tell a conversion from a standalone file. loadConfig reports the conversion itself.
func TestLoadConfigReportsConversionWithoutWarnings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[[EVM]]
ChainID = "1"
FinalityDepth = 42
[[EVM.Nodes]]
Name = "chainstack"
HTTPURL = "http://evm-node:8545"
`), 0o600))

	cfg, conversion, err := loadConfig(path)
	require.NoError(t, err)
	require.NotNil(t, conversion, "a converted node config must be reported as converted")
	require.Empty(t, conversion.Warnings, "nothing in this config is dropped")
	require.Contains(t, cfg.Chains, "5009297550715157269")
}

func TestLoadConfigReportsNoConversionForStandaloneConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[chains.5009297550715157269]
finality_depth = 42
[[chains.5009297550715157269.nodes]]
http_url = "http://evm-node:8545"
`), 0o600))

	_, conversion, err := loadConfig(path)
	require.NoError(t, err)
	require.Nil(t, conversion, "a standalone config was not converted")
}

// An EVM key with no usable chains is a node config the operator got wrong, not a standalone config.
// Classifying on the key's presence rather than its contents is what lets the converter say so;
// otherwise the node's own section comes back as an unknown field.
func TestLoadConfigClassifiesEmptyEVMKeyAsNodeConfig(t *testing.T) {
	tests := []struct {
		name string
		body string
		// Both cases must be reported as a problem with the node config rather than as an unknown
		// field, which is all the classification can promise; the table form fails in the parser
		// before the section count is ever reached.
		wantErr string
	}{
		{
			name:    "empty array",
			body:    "EVM = []\n",
			wantErr: "config has no [[EVM]] sections",
		},
		{
			name:    "table form",
			body:    "[EVM]\nChainID = \"1\"\n",
			wantErr: "failed to convert Chainlink node config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "evm.toml")
			require.NoError(t, os.WriteFile(path, []byte(tt.body), 0o600))

			_, _, err := loadConfig(path)
			require.ErrorContains(t, err, tt.wantErr)
			require.NotContains(t, err.Error(), "unknown fields in config",
				"the node's own EVM section must not come back as an unknown field")
		})
	}
}

// A file carrying both top-level tables is a concatenation accident, not a format: the converter
// would otherwise silently ignore the standalone section, which is exactly the kind of drop the
// strict decode exists to prevent.
func TestLoadConfigRejectsAConfigWithBothFormats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	body := "[chains.5009297550715157269]\n\n[[EVM]]\nChainID = \"1\"\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	_, _, err := loadConfig(path)
	require.ErrorContains(t, err, "both a top-level 'EVM' table and a top-level 'chains' table")
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
				Name:    "simplyvc",
				HTTPUrl: "http://evm-node:8545",
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
	require.Equal(t, "http://evm-node:8545", info.Nodes[0].HTTPUrl)
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte("unexpected = true\n"), 0o600))

	_, _, err := loadConfig(path)
	require.ErrorContains(t, err, "unknown fields in config")
}

func TestLoadConfigRejectsDerivedChainMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[chains.5009297550715157269]
chain_type = "ethereum"
unique_chain_name = "ethereum-mainnet"
`), 0o600))

	_, _, err := loadConfig(path)
	require.ErrorContains(t, err, "unknown fields in config")
	require.ErrorContains(t, err, "chain_type")
	require.ErrorContains(t, err, "unique_chain_name")
}

func TestLoadConfigRejectsUnexposedChainlinkEVMNodeFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[chains.5009297550715157269]
[[chains.5009297550715157269.nodes]]
http_url = "http://evm-node:8545"
SendOnly = true
`), 0o600))

	_, _, err := loadConfig(path)
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
				HTTPUrl: "http://127.0.0.1:1",
			}},
		},
	}

	factory, err := CreateAccessorFactory(logger.Test(t), chainaccess.GenericConfig{}, infos)
	require.NoError(t, err)
	require.NotNil(t, factory)
}
