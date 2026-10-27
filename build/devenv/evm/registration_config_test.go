package evm

import (
	"fmt"
	"os"
	"slices"
	"strconv"
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

func TestVerifierModifierLogPollerSourceReaderChains(t *testing.T) {
	output := &blockchain.Output{
		Family:  chainsel.FamilyEVM,
		ChainID: "1337",
		Nodes:   []*blockchain.Node{{InternalHTTPUrl: "http://evm-node:8545"}},
	}
	second := &blockchain.Output{
		Family:  chainsel.FamilyEVM,
		ChainID: "2337",
		Nodes:   []*blockchain.Node{{InternalHTTPUrl: "http://evm-node-2:8545"}},
	}
	outputs := []*blockchain.Output{output, second}
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

	// enabledChainIDs decodes the generated EVM config and returns the chain IDs that read through the LogPoller.
	enabledChainIDs := func(t *testing.T, config string) []string {
		var cfg accessorevm.Config
		_, err := toml.Decode(config, &cfg)
		require.NoError(t, err)
		var ids []string
		for _, selector := range cfg.LogPollerSourceReaderChains() {
			sel, err := strconv.ParseUint(selector, 10, 64)
			require.NoError(t, err)
			id, err := chainsel.GetChainIDFromSelector(sel)
			require.NoError(t, err)
			ids = append(ids, id)
		}
		slices.Sort(ids)
		return ids
	}

	t.Run("*: every chain reads through the LogPoller and the EVM secrets point at the verifier database", func(t *testing.T) {
		in := newInput(util.OpaqueConfig{"log_poller_source_reader_chains": []any{"*"}})
		req, err := VerifierModifier(testcontainers.ContainerRequest{}, in, outputs)
		require.NoError(t, err)
		files := mounted(t, req)
		require.Len(t, files, 2)
		require.Equal(t, []string{"1337", "2337"}, enabledChainIDs(t, files[accessorevm.DefaultEVMConfigPath]))

		var secrets evmconfig.Secrets
		_, err = toml.Decode(files[evmconfig.DefaultEVMSecretsPath], &secrets)
		require.NoError(t, err)
		require.NotNil(t, secrets.DB)
		require.Equal(t, committeeverifier.InternalDBURL(in, EVMDBName), secrets.DB.URL)
	})

	t.Run("listed chains: only those read through the LogPoller", func(t *testing.T) {
		in := newInput(util.OpaqueConfig{"log_poller_source_reader_chains": []any{"2337"}})
		req, err := VerifierModifier(testcontainers.ContainerRequest{}, in, outputs)
		require.NoError(t, err)
		files := mounted(t, req)
		require.Len(t, files, 2)
		require.Equal(t, []string{"2337"}, enabledChainIDs(t, files[accessorevm.DefaultEVMConfigPath]))
	})

	t.Run("a chain ID the verifier does not have is rejected", func(t *testing.T) {
		in := newInput(util.OpaqueConfig{"log_poller_source_reader_chains": []any{"1337", "9999"}})
		_, err := VerifierModifier(testcontainers.ContainerRequest{}, in, outputs)
		require.ErrorContains(t, err, "chain IDs [9999]")
	})

	t.Run("absent: RPC reader and no EVM secrets", func(t *testing.T) {
		req, err := VerifierModifier(testcontainers.ContainerRequest{}, newInput(nil), outputs)
		require.NoError(t, err)
		files := mounted(t, req)
		require.Len(t, files, 1)
		require.NotContains(t, files[accessorevm.DefaultEVMConfigPath], "log_poller_source_reader_enabled")
	})

	t.Run("an unknown key is rejected", func(t *testing.T) {
		_, err := VerifierModifier(testcontainers.ContainerRequest{}, newInput(util.OpaqueConfig{"log_poller_enabled": true}), outputs)
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

	got, err := VerifierDatabases(newInput(util.OpaqueConfig{"log_poller_source_reader_chains": []any{"*"}}))
	require.NoError(t, err)
	require.Equal(t, []string{EVMDBName}, got, "the LogPoller needs evm_db")

	got, err = VerifierDatabases(newInput(nil))
	require.NoError(t, err)
	require.Empty(t, got, "the RPC reader needs no extra database")
}

func TestLogPollerSourceReaderOn(t *testing.T) {
	newInput := func(chains ...any) *committeeverifier.Input {
		in := &committeeverifier.Input{ContainerName: "default-verifier-1"}
		if chains != nil {
			in.OpaqueConfigs = map[string]util.OpaqueConfig{chainsel.FamilyEVM: {"log_poller_source_reader_chains": chains}}
		}
		return in
	}
	for _, tc := range []struct {
		name string
		in   *committeeverifier.Input
		want bool
	}{
		{"all chains", newInput("*"), true},
		{"listed chain", newInput("1337"), true},
		{"other chain", newInput("2337"), false},
		{"no opaque config", newInput(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LogPollerSourceReaderOn(tc.in, "1337")
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
