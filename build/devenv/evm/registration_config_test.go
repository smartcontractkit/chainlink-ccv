package evm

import (
	"io"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	chainsel "github.com/smartcontractkit/chain-selectors"
	accessorevm "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func TestEVMConfigIsMountedSeparatelyFromAppConfig(t *testing.T) {
	output := &blockchain.Output{
		Type:          "anvil",
		Family:        chainsel.FamilyEVM,
		ContainerName: "evm-node",
		ChainID:       "1337",
		Nodes: []*blockchain.Node{{
			ExternalHTTPUrl: "http://localhost:8545",
			InternalHTTPUrl: "http://evm-node:8545",
			ExternalWSUrl:   "ws://localhost:8546",
			InternalWSUrl:   "ws://evm-node:8546",
		}},
	}

	placeholders, err := ChainConfigLoader([]*blockchain.Output{output})
	require.NoError(t, err)
	require.Len(t, placeholders, 1)
	for _, raw := range placeholders {
		metadata, ok := raw.(accessorevm.Info)
		require.True(t, ok)
		require.Equal(t, output.ChainID, metadata.ChainID)
		require.Equal(t, output.Family, metadata.Family)
		require.Empty(t, metadata.Nodes)
	}

	req, err := addEVMConfig(testcontainers.ContainerRequest{}, []*blockchain.Output{output})
	require.NoError(t, err)
	require.Len(t, req.Files, 1)
	require.Equal(t, accessorevm.DefaultEVMConfigPath, req.Files[0].ContainerFilePath)
	require.Equal(t, int64(0o644), req.Files[0].FileMode)

	data, err := io.ReadAll(req.Files[0].Reader)
	require.NoError(t, err)
	var cfg accessorevm.Config
	md, err := toml.Decode(string(data), &cfg)
	require.NoError(t, err)
	require.Empty(t, md.Undecoded())
	require.Len(t, cfg.BlockchainInfos, 1)
	for _, info := range cfg.BlockchainInfos {
		require.Equal(t, output.ChainID, info.ChainID)
		require.Equal(t, output.Nodes[0].InternalHTTPUrl, info.Nodes[0].InternalHTTPUrl)
	}
}
