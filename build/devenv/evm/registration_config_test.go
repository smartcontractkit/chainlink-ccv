package evm

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	accessorevm "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
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
	require.False(t, cfg.LogPollerEnabled)
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

func TestVerifierModifierLogPollerEnabled(t *testing.T) {
	output := &blockchain.Output{
		Family:  chainsel.FamilyEVM,
		ChainID: "1337",
		Nodes:   []*blockchain.Node{{InternalHTTPUrl: "http://evm-node:8545"}},
	}
	// The secrets file is written to the devenv config dir, which util creates under HOME at init.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	require.NoError(t, os.MkdirAll(util.CCVConfigDir(), 0o700))
	newInput := func(opaque util.OpaqueConfig) *committeeverifier.Input {
		in := committeeverifier.ApplyDefaults(committeeverifier.Input{ContainerName: "default-verifier-1", CommitteeName: "default"})
		if opaque != nil {
			in.OpaqueConfigs = map[string]util.OpaqueConfig{chainsel.FamilyEVM: opaque}
		}
		return &in
	}
	// mounted reads each copied or bind-mounted file by its container path.
	mounted := func(t *testing.T, req testcontainers.ContainerRequest) map[string]string {
		files := make(map[string]string)
		for _, f := range req.Files {
			data, err := os.ReadFile(f.HostFilePath)
			require.NoError(t, err)
			t.Cleanup(func() { _ = os.Remove(f.HostFilePath) })
			files[f.ContainerFilePath] = string(data)
		}
		for _, m := range req.Mounts {
			source, ok := m.Source.(testcontainers.GenericBindMountSource)
			require.True(t, ok)
			data, err := os.ReadFile(source.HostPath)
			require.NoError(t, err)
			files[string(m.Target)] = string(data)
		}
		return files
	}

	t.Run("on: the EVM config enables it and the EVM secrets point at the verifier database", func(t *testing.T) {
		in := newInput(util.OpaqueConfig{"log_poller_enabled": true})
		req, err := VerifierModifier(testcontainers.ContainerRequest{}, in, []*blockchain.Output{output})
		require.NoError(t, err)
		files := mounted(t, req)
		require.Len(t, files, 2)

		var cfg accessorevm.Config
		_, err = toml.Decode(files[accessorevm.DefaultEVMConfigPath], &cfg)
		require.NoError(t, err)
		require.True(t, cfg.LogPollerEnabled)

		var secrets evmconfig.Secrets
		_, err = toml.Decode(files[evmconfig.DefaultEVMSecretsPath], &secrets)
		require.NoError(t, err)
		require.NotNil(t, secrets.DB)
		require.Equal(t, committeeverifier.InternalDBURL(in, evmDBName), secrets.DB.URL)
		require.FileExists(t, filepath.Join(util.CCVConfigDir(), "evm-default-secrets-1.toml"))
	})

	t.Run("absent: RPC reader and no EVM secrets", func(t *testing.T) {
		req, err := VerifierModifier(testcontainers.ContainerRequest{}, newInput(nil), []*blockchain.Output{output})
		require.NoError(t, err)
		files := mounted(t, req)
		require.Len(t, files, 1)
		require.NotContains(t, files[accessorevm.DefaultEVMConfigPath], "log_poller_enabled")
	})

	t.Run("an unknown key is rejected", func(t *testing.T) {
		_, err := VerifierModifier(testcontainers.ContainerRequest{}, newInput(util.OpaqueConfig{"log_poller": true}), []*blockchain.Output{output})
		require.ErrorContains(t, err, "opaque_configs.evm")
	})
}

func TestVerifierDatabases(t *testing.T) {
	newInput := func(opaque util.OpaqueConfig) *committeeverifier.Input {
		in := &committeeverifier.Input{ContainerName: "default-verifier-1"}
		if opaque != nil {
			in.OpaqueConfigs = map[string]util.OpaqueConfig{chainsel.FamilyEVM: opaque}
		}
		return in
	}

	got, err := VerifierDatabases(newInput(util.OpaqueConfig{"log_poller_enabled": true}))
	require.NoError(t, err)
	require.Equal(t, []string{evmDBName}, got, "the LogPoller needs evm_db")

	got, err = VerifierDatabases(newInput(nil))
	require.NoError(t, err)
	require.Empty(t, got, "the RPC reader needs no extra database")

	_, err = VerifierDatabases(newInput(util.OpaqueConfig{"log_poller": true}))
	require.ErrorContains(t, err, "invalid opaque_configs.evm")
}
