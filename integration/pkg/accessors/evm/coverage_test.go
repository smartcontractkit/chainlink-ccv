package evm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// 5009297550715157269 is Ethereum mainnet (chain ID 1) and 4051577828743386545 is Polygon
// (chain ID 137) in chain-selectors.
const (
	ethMainnetSelector = "5009297550715157269"
	polygonSelector    = "4051577828743386545"
)

// standaloneChainTOML is a minimal servable [chains.<selector>] section: coverage now requires a
// chain to be buildable, not merely present, so a fixture meaning "covered" needs an RPC node.
func standaloneChainTOML(selector string) string {
	return "[chains." + selector + "]\n" +
		"[[chains." + selector + ".nodes]]\n" +
		"name = 'primary'\n" +
		"http_url = 'https://rpc.example.com'\n"
}

func writeEVMConfigFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// The EVM declared-chain coverage checker: every EVM chain the operator declares in the bootstrap
// config's [[chains]] must be servable by the mounted EVM config, in either format. Without it a
// missing or unconvertible chain surfaces only when the first message for it arrives. These run
// sequentially: the checker reads the config path from EVM_CONFIG_PATH, set per subtest.
func TestCheckDeclaredChainCoverage(t *testing.T) {
	t.Run("declared chains covered by a standalone config", func(t *testing.T) {
		path := writeEVMConfigFile(t, standaloneChainTOML(ethMainnetSelector)+standaloneChainTOML(polygonSelector))
		t.Setenv(EVMConfigPathEnv, path)
		require.NoError(t, checkDeclaredChainCoverage([]string{"1", "137"}))
	})

	t.Run("declared chains covered by a converted node config", func(t *testing.T) {
		path := writeEVMConfigFile(t, `
[[EVM]]
ChainID = '1'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://eth.example.com'
`)
		t.Setenv(EVMConfigPathEnv, path)
		require.NoError(t, checkDeclaredChainCoverage([]string{"1"}))
	})

	t.Run("a declared chain missing from the config names the chain and its selector", func(t *testing.T) {
		path := writeEVMConfigFile(t, standaloneChainTOML(ethMainnetSelector))
		t.Setenv(EVMConfigPathEnv, path)
		err := checkDeclaredChainCoverage([]string{"1", "137"})
		require.ErrorContains(t, err, "cannot serve")
		require.ErrorContains(t, err, "chain 137 (selector "+polygonSelector+")")
		require.ErrorContains(t, err, "no section for it")
		require.NotContains(t, err.Error(), "chain 1 (",
			"the covered chain must not be named as missing")
	})

	t.Run("a declared chain that failed to convert names the conversion reason", func(t *testing.T) {
		path := writeEVMConfigFile(t, `
[[EVM]]
ChainID = '137'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://polygon.example.com'

[[EVM]]
ChainID = '1'
[[EVM.Nodes]]
Name = 'ws-only'
WSURL = 'wss://eth.example.com'
`)
		t.Setenv(EVMConfigPathEnv, path)
		err := checkDeclaredChainCoverage([]string{"1"})
		require.ErrorContains(t, err, "chain 1 (selector "+ethMainnetSelector+")")
		require.ErrorContains(t, err, "did not convert")
		require.ErrorContains(t, err, "no HTTPURL")
	})

	t.Run("a declared id with no known chain selector is a config typo", func(t *testing.T) {
		path := writeEVMConfigFile(t, standaloneChainTOML(ethMainnetSelector))
		t.Setenv(EVMConfigPathEnv, path)
		err := checkDeclaredChainCoverage([]string{"88888888888888"})
		require.ErrorContains(t, err, "chain 88888888888888")
		require.ErrorContains(t, err, "no known EVM chain selector")
	})

	t.Run("chains declared but the config file is absent", func(t *testing.T) {
		absent := filepath.Join(t.TempDir(), "absent.toml")
		t.Setenv(EVMConfigPathEnv, absent)
		err := checkDeclaredChainCoverage([]string{"1"})
		require.ErrorContains(t, err, "cannot be loaded")
		require.ErrorContains(t, err, absent, "the wrapped error names the path that was read")
	})

	// Presence is not servability. A section with no nodes decodes fine and used to pass this
	// guard, failing only when the first accessor was built at job start.
	t.Run("a declared chain whose section cannot serve it fails the boot", func(t *testing.T) {
		path := writeEVMConfigFile(t, "[chains."+ethMainnetSelector+"]\n")
		t.Setenv(EVMConfigPathEnv, path)
		err := checkDeclaredChainCoverage([]string{"1"})
		require.ErrorContains(t, err, "chain 1 (selector "+ethMainnetSelector+")")
		require.ErrorContains(t, err, "cannot serve it")
		require.ErrorContains(t, err, "no RPC nodes")
	})

	t.Run("extra configured chains beyond the declaration are fine", func(t *testing.T) {
		path := writeEVMConfigFile(t, standaloneChainTOML(ethMainnetSelector)+standaloneChainTOML(polygonSelector))
		t.Setenv(EVMConfigPathEnv, path)
		require.NoError(t, checkDeclaredChainCoverage([]string{"1"}))
	})

	// A chain the operator disabled in the node config is an explicit choice, not a gap: CL mode
	// was not serving it either, so the declaration stays (it registers the signing key) and the
	// boot must not fail. Failing here would crash-loop a legitimate incident-remediation state.
	t.Run("a declared chain the node disabled explicitly passes", func(t *testing.T) {
		path := writeEVMConfigFile(t, `
[[EVM]]
ChainID = '137'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://polygon.example.com'

[[EVM]]
ChainID = '1'
Enabled = false
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://eth.example.com'
`)
		t.Setenv(EVMConfigPathEnv, path)
		require.NoError(t, checkDeclaredChainCoverage([]string{"1", "137"}))
	})

	t.Run("no declared chains: nothing to check, the config need not exist", func(t *testing.T) {
		t.Setenv(EVMConfigPathEnv, filepath.Join(t.TempDir(), "absent.toml"))
		require.NoError(t, checkDeclaredChainCoverage(nil))
	})
}
