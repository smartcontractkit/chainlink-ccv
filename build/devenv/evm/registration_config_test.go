package evm

import (
	"fmt"
	"os"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
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

	req, err := addEVMConfig(testcontainers.ContainerRequest{}, []*blockchain.Output{output}, "")
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

func readMountedEVMConfig(t *testing.T, req testcontainers.ContainerRequest) (accessorevm.Config, string) {
	t.Helper()
	require.Len(t, req.Files, 1)
	t.Cleanup(func() { require.NoError(t, os.Remove(req.Files[0].HostFilePath)) })
	data, err := os.ReadFile(req.Files[0].HostFilePath)
	require.NoError(t, err)
	var cfg accessorevm.Config
	_, err = toml.Decode(string(data), &cfg)
	require.NoError(t, err)
	return cfg, string(data)
}

// log_poller_mode is per verifier, so one committee member can run on the poller beside an RPC peer.
func TestVerifierLogPollerModeReachesEveryChain(t *testing.T) {
	outputs := []*blockchain.Output{
		{
			Type: "anvil", Family: chainsel.FamilyEVM, ContainerName: "evm-a", ChainID: "1337",
			Nodes: []*blockchain.Node{{InternalHTTPUrl: "http://evm-a:8545", InternalWSUrl: "ws://evm-a:8546"}},
		},
		{
			Type: "anvil", Family: chainsel.FamilyEVM, ContainerName: "evm-b", ChainID: "2337",
			Nodes: []*blockchain.Node{{InternalHTTPUrl: "http://evm-b:8545", InternalWSUrl: "ws://evm-b:8546"}},
		},
	}

	t.Run("verifier with a mode", func(t *testing.T) {
		req, err := VerifierModifier(testcontainers.ContainerRequest{},
			&committeeverifier.Input{ContainerName: "v1", LogPollerMode: "read"}, outputs)
		require.NoError(t, err)
		cfg, _ := readMountedEVMConfig(t, req)
		require.Len(t, cfg.Chains, 2)
		for selector, chain := range cfg.Chains {
			require.EqualValues(t, "read", chain.LogPollerMode, selector)
		}
	})

	t.Run("verifier without a mode", func(t *testing.T) {
		req, err := VerifierModifier(testcontainers.ContainerRequest{},
			&committeeverifier.Input{ContainerName: "v2"}, outputs)
		require.NoError(t, err)
		_, raw := readMountedEVMConfig(t, req)
		require.NotContains(t, raw, "log_poller_mode")
	})

	t.Run("executor", func(t *testing.T) {
		req, err := ExecutorModifier(testcontainers.ContainerRequest{}, &executor.Input{ContainerName: "e1"}, outputs)
		require.NoError(t, err)
		_, raw := readMountedEVMConfig(t, req)
		require.NotContains(t, raw, "log_poller_mode")
	})
}
