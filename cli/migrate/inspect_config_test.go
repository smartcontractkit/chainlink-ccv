package migrate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfigFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

// The report the pre-cutover diff prints: the conversion warnings name what the node config set
// that standalone drops, and the chain projection shows what standalone will run instead.
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

		assert.Contains(t, report.Warnings, "chain 11155111: dropped set chain-level settings with no standalone equivalent: GasEstimator.Mode")
		assert.Contains(t, report.Warnings, "chain 11155111 node send-only: dropped, SendOnly nodes have no standalone equivalent")
	})

	t.Run("unset block time is reported as the fallback", func(t *testing.T) {
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
		assert.Equal(t, "2s", chain.TXMBlockTime)
		assert.True(t, chain.TXMBlockTimeIsDefault)
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
Mode = 'BlockHistory'
[[EVM.Nodes]]
Name = 'sepolia'
HTTPURL = 'https://sepolia.example.com'

[[EVM]]
ChainID = '421614'
[EVM.HeadTracker]
HistoryDepth = 50
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
		assert.Contains(t, report.Warnings[0], "chain 421614: dropped set chain-level settings")

		_, err = buildConfigReport(path, "999")
		require.ErrorContains(t, err, "not in")
	})
}
