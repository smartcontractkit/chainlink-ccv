package evm

import (
	"fmt"
	"os"
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
		Nodes: []*blockchain.Node{
			{
				ExternalHTTPUrl: "http://localhost:8545",
				InternalHTTPUrl: "http://evm-node:8545",
				ExternalWSUrl:   "ws://localhost:8546",
				InternalWSUrl:   "ws://evm-node:8546",
			},
			{
				ExternalHTTPUrl: "http://localhost:9545",
				InternalHTTPUrl: "http://evm-node-secondary:8545",
				ExternalWSUrl:   "ws://localhost:9546",
				InternalWSUrl:   "ws://evm-node-secondary:8546",
			},
		},
	}

	metadataBySelector, err := ChainConfigLoader([]*blockchain.Output{output})
	require.NoError(t, err)
	require.Len(t, metadataBySelector, 1)
	for _, raw := range metadataBySelector {
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
	require.Nil(t, req.Files[0].Reader)
	require.NotEmpty(t, req.Files[0].HostFilePath)
	t.Cleanup(func() { require.NoError(t, os.Remove(req.Files[0].HostFilePath)) })

	data, err := os.ReadFile(req.Files[0].HostFilePath)
	require.NoError(t, err)
	// HostFilePath is reopened by testcontainers for every container-start attempt. Reading it twice
	// locks in the retry-safe behavior that a one-shot ContainerFile.Reader cannot provide.
	retryData, err := os.ReadFile(req.Files[0].HostFilePath)
	require.NoError(t, err)
	require.Equal(t, data, retryData)
	var cfg accessorevm.Config
	md, err := toml.Decode(string(data), &cfg)
	require.NoError(t, err)
	require.Empty(t, md.Undecoded())
	require.Len(t, cfg.Chains, 1)
	// Chain ID, family, and chain type are intentionally absent from the mounted
	// file because they are derived from the selector.
	for _, chain := range cfg.Chains {
		require.Len(t, chain.Nodes, len(output.Nodes))
		// Standalone services read this file from inside the devenv Docker network, so the
		// generated config carries CTF's container-reachable URLs and not its host-facing ones.
		for i, node := range output.Nodes {
			require.Equal(t, fmt.Sprintf("evm-node-%d", i+1), chain.Nodes[i].Name)
			require.Equal(t, node.InternalHTTPUrl, chain.Nodes[i].HTTPUrl)
			require.Equal(t, node.InternalWSUrl, chain.Nodes[i].WSUrl)
		}
	}
	require.NotContains(t, string(data), "internal_http_url")
	require.NotContains(t, string(data), "external_http_url")
}
