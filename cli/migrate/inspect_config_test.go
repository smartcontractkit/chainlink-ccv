package migrate

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
)

func writeConfigFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

// The report the pre-cutover diff prints: the conversion warnings name where standalone runs
// differently from the node config, and the chain projection shows what standalone will run.
func TestBuildConfigReport(t *testing.T) {
	t.Parallel()

	t.Run("node config: conversion, warnings, and effective settings", func(t *testing.T) {
		t.Parallel()
		path := writeConfigFile(t, `
[[EVM]]
ChainID = '11155111'
FinalityDepth = 22
FinalityTagEnabled = false
[EVM.Transactions.TransactionManagerV2]
BlockTime = '12s'
[EVM.GasEstimator]
Mode = 'BlockHistory'
[EVM.BalanceMonitor]
Enabled = true

[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
WSURL = 'wss://sepolia.example.com'

[[EVM.Nodes]]
Name = 'send-only'
HTTPURL = 'https://sepolia-so.example.com'
SendOnly = true
`)

		report, err := buildConfigReport(path, "")
		require.NoError(t, err)

		assert.True(t, report.ConvertedFromNodeConfig)
		require.Len(t, report.Chains, 1)
		chain := report.Chains["16015286601757825753"] // ethereum-sepolia
		assert.Equal(t, uint32(22), chain.FinalityDepth)
		assert.Equal(t, "12s", chain.TXMBlockTime)
		assert.False(t, chain.TXMBlockTimeIsDefault)
		require.Len(t, chain.Nodes, 1, "the send-only node is dropped")
		require.Len(t, report.BroadcastEndpoints, 1)
		assert.Equal(t, 2, report.BroadcastEndpoints[0].LegacyEndpoints)
		assert.Equal(t, 1, report.BroadcastEndpoints[0].StandaloneEndpoints)
		assert.True(t, report.BroadcastEndpoints[0].ReviewRequired)
		assert.True(t, report.ConversionReviewRequired)

		assert.Equal(t, []string{
			"chain 11155111 node send-only: dropped SendOnly broadcast-only node; standalone has no send-only role. Add a standard node only if it is safe for reads and broadcast, or approve reduced redundancy",
		}, report.Warnings, "GasEstimator.Mode and BalanceMonitor.Enabled carry over, so they are not deviations")
		assert.Equal(t, evmconfig.ChainDefaultsSource(), report.ChainDefaults)
		assert.Empty(t, report.ChainDefaultsProblems)
	})

	t.Run("unset block time on a curated chain reports the chain default", func(t *testing.T) {
		t.Parallel()
		path := writeConfigFile(t, `
[[EVM]]
ChainID = '11155111'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`)

		report, err := buildConfigReport(path, "")
		require.NoError(t, err)
		chain := report.Chains["16015286601757825753"]
		assert.Equal(t, "12s", chain.TXMBlockTime)
		assert.True(t, chain.TXMBlockTimeIsDefault)
		assert.Equal(t, "curated_chain_default", chain.TXMBlockTimeSource)
	})

	t.Run("standalone format needs no conversion", func(t *testing.T) {
		t.Parallel()
		path := writeConfigFile(t, `
[chains."16015286601757825753"]
finality_depth = 30
txm_block_time = "12s"
[[chains."16015286601757825753".nodes]]
name = "primary"
http_url = "https://sepolia.example.com"
`)

		report, err := buildConfigReport(path, "")
		require.NoError(t, err)
		assert.False(t, report.ConvertedFromNodeConfig)
		assert.Empty(t, report.Warnings)
		assert.Equal(t, uint32(30), report.Chains["16015286601757825753"].FinalityDepth)
	})

	// A per-chain report has to narrow its warnings too: another chain's dropped settings printed
	// next to this chain's settings read as this chain's deviations.
	t.Run("chain-selector filters the chains and their warnings", func(t *testing.T) {
		t.Parallel()
		path := writeConfigFile(t, `
[[EVM]]
ChainID = '11155111'
[EVM.GasEstimator]
FutureSetting = 'x'
[[EVM.Nodes]]
Name = 'sepolia'
HTTPURL = 'https://sepolia.example.com'

[[EVM]]
ChainID = '421614'
[EVM.HeadTracker]
FutureSetting = 50
[[EVM.Nodes]]
Name = 'arb'
HTTPURL = 'https://arb.example.com'
`)

		full, err := buildConfigReport(path, "")
		require.NoError(t, err)
		require.Len(t, full.Warnings, 2, "one dropped setting per chain")

		report, err := buildConfigReport(path, "3478487238524512106") // arbitrum-sepolia
		require.NoError(t, err)
		require.Len(t, report.Chains, 1)
		assert.Contains(t, report.Chains, "3478487238524512106")
		require.Len(t, report.Warnings, 1)
		assert.Contains(t, report.Warnings[0], "chain 421614: dropped set chain-level settings unknown to this release")

		_, err = buildConfigReport(path, "999")
		require.ErrorContains(t, err, "not in")
	})

	// A chain whose [[EVM]] section cannot run standalone is skipped by the conversion rather than
	// failing the report: the review must see the skip and its reason, because that chain will not
	// be served at all.
	t.Run("a chain that fails conversion is reported, not fatal", func(t *testing.T) {
		t.Parallel()
		path := writeConfigFile(t, `
[[EVM]]
ChainID = '11155111'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'

[[EVM]]
ChainID = '421614'
[[EVM.Nodes]]
Name = 'ws-only'
WSURL = 'wss://arb.example.com'

[[EVM]]
ChainID = '88888888888888'
[[EVM.Nodes]]
Name = 'mystery'
HTTPURL = 'https://mystery.example.com'
`)

		report, err := buildConfigReport(path, "")
		require.NoError(t, err)
		assert.Len(t, report.Chains, 1, "only the healthy chain projects")
		assert.Contains(t, report.Chains, "16015286601757825753")

		require.Len(t, report.FailedChains, 2)
		assert.Equal(t, "421614", report.FailedChains[0].ChainID)
		assert.Contains(t, report.FailedChains[0].Reason, "node ws-only has no HTTPURL")
		assert.Equal(t, "88888888888888", report.FailedChains[1].ChainID)
		assert.Contains(t, report.FailedChains[1].Reason, "no known chain selector")

		assert.Contains(t, report.Warnings, "chain 421614: skipped, node ws-only has no HTTPURL; standalone CCV requires an HTTP endpoint for every node")
	})

	// Narrowing to a chain that failed conversion must answer "what happens to my chain" — the
	// failure, with its reason — instead of a bare not-in-config error.
	t.Run("chain-selector on a failed chain reports the failure", func(t *testing.T) {
		t.Parallel()
		path := writeConfigFile(t, `
[[EVM]]
ChainID = '11155111'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'

[[EVM]]
ChainID = '421614'
[[EVM.Nodes]]
Name = 'ws-only'
WSURL = 'wss://arb.example.com'
`)

		report, err := buildConfigReport(path, "3478487238524512106") // arbitrum-sepolia
		require.NoError(t, err)
		assert.Empty(t, report.Chains)
		require.Len(t, report.FailedChains, 1)
		assert.Equal(t, "421614", report.FailedChains[0].ChainID)
		assert.Contains(t, report.FailedChains[0].Reason, "no HTTPURL")
		require.Len(t, report.Warnings, 1)
		assert.Contains(t, report.Warnings[0], "chain 421614: skipped")
	})

	// The ignored top-level sections are file-level: they are named in every report, including a
	// chain-narrowed one, so the review sees what the conversion did not read at all.
	t.Run("ignored top-level sections are named and survive chain narrowing", func(t *testing.T) {
		t.Parallel()
		path := writeConfigFile(t, `
[Log]
Level = 'debug'

[WebServer]
HTTPPort = 6688

[[EVM]]
ChainID = '11155111'
[[EVM.Nodes]]
Name = 'sepolia'
HTTPURL = 'https://sepolia.example.com'
`)

		full, err := buildConfigReport(path, "")
		require.NoError(t, err)
		assert.Equal(t, []string{"Log", "WebServer"}, full.IgnoredSections)

		narrowed, err := buildConfigReport(path, "16015286601757825753")
		require.NoError(t, err)
		assert.Equal(t, full.IgnoredSections, narrowed.IgnoredSections)
	})
}

const inventoryPreflightEVMConfig = `
[chains."5009297550715157269"]
[[chains."5009297550715157269".nodes]]
name = "eth"
http_url = "https://eth.example.com"
[chains."4051577828743386545"]
[[chains."4051577828743386545".nodes]]
name = "polygon"
http_url = "https://polygon.example.com"
`

func TestInspectConfigBootstrapPreflight(t *testing.T) {
	evmPath := writeConfigFile(t, inventoryPreflightEVMConfig)

	t.Run("valid inventory passes", func(t *testing.T) {
		bootstrapPath := writeConfigFile(t, `
[[chains]]
type = "EVM"
id = "1"
[[chains]]
type = "EVM"
id = "137"
`)
		report, err := buildConfigReportWithBootstrap(evmPath, "", bootstrapPath)
		require.NoError(t, err)
		require.NotNil(t, report.ChainInventory)
		require.NoError(t, report.ChainInventory.Err())
	})

	t.Run("empty and missing declarations are diagnosed", func(t *testing.T) {
		bootstrapPath := writeConfigFile(t, "")
		report, err := buildConfigReportWithBootstrap(evmPath, "", bootstrapPath)
		require.NoError(t, err)
		require.True(t, report.ChainInventory.Empty)
		require.Equal(t, []string{"1", "137"}, report.ChainInventory.MissingDeclarations)
	})

	t.Run("extra declaration is diagnosed", func(t *testing.T) {
		oneChainPath := writeConfigFile(t, `
[chains."5009297550715157269"]
[[chains."5009297550715157269".nodes]]
name = "eth"
http_url = "https://eth.example.com"
`)
		bootstrapPath := writeConfigFile(t, `
[[chains]]
type = "EVM"
id = "1"
[[chains]]
type = "EVM"
id = "137"
`)
		report, err := buildConfigReportWithBootstrap(oneChainPath, "", bootstrapPath)
		require.NoError(t, err)
		require.Equal(t, []string{"137"}, report.ChainInventory.ExtraDeclarations)
	})

	t.Run("duplicate and unsupported declarations are diagnosed", func(t *testing.T) {
		bootstrapPath := writeConfigFile(t, `
[[chains]]
type = "EVM"
id = "1"
[[chains]]
type = "EVM"
id = "1"
[[chains]]
type = "EVM"
id = "137"
[[chains]]
type = "SOLANA"
id = "1"
`)
		report, err := buildConfigReportWithBootstrap(evmPath, "", bootstrapPath)
		require.NoError(t, err)
		require.Equal(t, []string{"1"}, report.ChainInventory.DuplicateDeclarations)
		require.Contains(t, report.ChainInventory.UnsupportedDeclarations[0], "SOLANA/1")
	})

	t.Run("command exits nonzero after rendering a mismatch", func(t *testing.T) {
		bootstrapPath := writeConfigFile(t, "")
		command := inspectConfigCommand()
		app := cli.NewApp()
		app.Commands = []cli.Command{command}
		err := app.Run([]string{"ccv", "inspect-config", "--config", evmPath, "--bootstrap-config", bootstrapPath})
		require.ErrorContains(t, err, "inventory is empty")
		require.ErrorContains(t, err, "missing")
	})
}

func TestInspectConfigMantleLimitMultiplier(t *testing.T) {
	details, err := chainsel.GetChainDetailsByChainIDAndFamily("5000", chainsel.FamilyEVM)
	require.NoError(t, err)
	selector := fmt.Sprintf("%d", details.ChainSelector)

	t.Run("conversion reports the safe effective override", func(t *testing.T) {
		path := writeConfigFile(t, `
[[EVM]]
ChainID = '5000'
[EVM.GasEstimator]
LimitMultiplier = '23000'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://mantle.example.com'
`)
		report, err := buildConfigReport(path, "")
		require.NoError(t, err)
		require.Equal(t, "1", report.Chains[selector].GasEstimatorLimitMultiplier)
		require.Contains(t, report.Warnings[0], "overrides GasEstimator.LimitMultiplier = 23000")
	})

	t.Run("unsafe standalone config fails preflight", func(t *testing.T) {
		path := writeConfigFile(t, fmt.Sprintf(`
[chains."%[1]s"]
gas_estimator_limit_multiplier = '23000'
[[chains."%[1]s".nodes]]
name = "primary"
http_url = "https://mantle.example.com"
`, selector))
		_, err := buildConfigReport(path, "")
		require.ErrorContains(t, err, "Mantle chain 5000")
		require.ErrorContains(t, err, "LimitMultiplier = 23000")
		require.ErrorContains(t, err, "gas_estimator_limit_multiplier = 1")
	})
}
