package evm

import (
	"math/big"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
)

// Chain selectors for the chain IDs used below, so the expectations read as the operator's chain
// rather than as an opaque number.
const (
	sepoliaChainID  = "11155111"
	sepoliaSelector = "16015286601757825753"
	arbSepChainID   = "421614"
	arbSepSelector  = "3478487238524512106"
)

func TestConvertChainlinkNodeConfig(t *testing.T) {
	t.Parallel()

	t.Run("maps chains, nodes and endpoints", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[Log]
Level = 'info'

[[EVM]]
ChainID = '` + sepoliaChainID + `'
FinalityTagEnabled = false
FinalityDepth = 22

[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
WSURL = 'wss://sepolia.example.com'

[[EVM.Nodes]]
Name = 'backup'
HTTPURL = 'https://sepolia-backup.example.com'
`))
		require.NoError(t, err)
		require.Len(t, got.Config.Chains, 1)

		chain := got.Config.Chains[sepoliaSelector]
		assert.Equal(t, uint32(22), chain.FinalityDepth)
		require.Len(t, chain.Nodes, 2)
		assert.Equal(t, Node{
			Name:    "primary",
			HTTPUrl: "https://sepolia.example.com",
			WSUrl:   "wss://sepolia.example.com",
		}, chain.Nodes[0])
		assert.Equal(t, Node{
			Name:    "backup",
			HTTPUrl: "https://sepolia-backup.example.com",
		}, chain.Nodes[1], "a node without a WSURL converts to HTTP-only, not to an empty ws_url string")
		assert.Empty(t, got.Warnings)
	})

	t.Run("converts several chains", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'sepolia'
HTTPURL = 'https://sepolia.example.com'

[[EVM]]
ChainID = '` + arbSepChainID + `'
[[EVM.Nodes]]
Name = 'arb'
HTTPURL = 'https://arb.example.com'
`))
		require.NoError(t, err)
		assert.Len(t, got.Config.Chains, 2)
		assert.Contains(t, got.Config.Chains, sepoliaSelector)
		assert.Contains(t, got.Config.Chains, arbSepSelector)
	})

	t.Run("finality tags convert to a zero depth", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
FinalityTagEnabled = true
FinalityDepth = 50
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`))
		require.NoError(t, err)
		assert.Equal(t, uint32(0), got.Config.Chains[sepoliaSelector].FinalityDepth,
			"finality-tag mode is expressed as a zero depth, and the unused FinalityDepth must not leak through")
	})

	t.Run("an unset finality mode follows the chain default rather than assuming tags", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`))
		require.NoError(t, err)
		// Whichever mode the node defaults Sepolia to, the converted config has to reproduce it. The
		// bug this guards against is emitting a zero depth — finality-tag mode — for a chain the node
		// actually runs on confirmation depth.
		chain := got.Config.Chains[sepoliaSelector]
		assert.Equal(t, sepoliaDefaultFinalityDepth(t), chain.FinalityDepth)
	})

	t.Run("carries an explicit TXM block time and leaves an unset one to the standalone default", func(t *testing.T) {
		t.Parallel()
		withOverride, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[EVM.Transactions.TransactionManagerV2]
BlockTime = '7s'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`))
		require.NoError(t, err)
		assert.Equal(t, 7*time.Second, withOverride.Config.Chains[sepoliaSelector].TXMBlockTime)

		without, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`))
		require.NoError(t, err)
		assert.Equal(t, time.Duration(0), without.Config.Chains[sepoliaSelector].TXMBlockTime)
	})

	t.Run("later blocks for the same chain override earlier ones", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
FinalityTagEnabled = false
FinalityDepth = 10
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'

[[EVM]]
ChainID = '` + sepoliaChainID + `'
FinalityDepth = 99
`))
		require.NoError(t, err)
		require.Len(t, got.Config.Chains, 1)
		assert.Equal(t, uint32(99), got.Config.Chains[sepoliaSelector].FinalityDepth)
	})

	t.Run("drops send-only nodes with a warning", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'

[[EVM.Nodes]]
Name = 'broadcast-only'
HTTPURL = 'https://sepolia-broadcast.example.com'
SendOnly = true
`))
		require.NoError(t, err)
		require.Len(t, got.Config.Chains[sepoliaSelector].Nodes, 1)
		assert.Equal(t, "primary", got.Config.Chains[sepoliaSelector].Nodes[0].Name)
		require.Len(t, got.Warnings, 1)
		assert.Contains(t, got.Warnings[0], "broadcast-only")
		assert.Contains(t, got.Warnings[0], "SendOnly")
	})

	t.Run("warns about settings with no standalone equivalent", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
Order = 50
`))
		require.NoError(t, err)
		require.Len(t, got.Warnings, 1)
		assert.Contains(t, got.Warnings[0], "Order")
		assert.Len(t, got.Config.Chains[sepoliaSelector].Nodes, 1)
	})

	t.Run("skips a disabled chain with a warning", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
Enabled = false
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'

[[EVM]]
ChainID = '` + arbSepChainID + `'
[[EVM.Nodes]]
Name = 'arb'
HTTPURL = 'https://arb.example.com'
`))
		require.NoError(t, err)
		assert.Len(t, got.Config.Chains, 1)
		assert.Contains(t, got.Config.Chains, arbSepSelector)
		require.Len(t, got.Warnings, 1)
		assert.Contains(t, got.Warnings[0], "disabled")
	})
}

// TestConvertedConfigLoadsStrictly encodes a conversion the way the CLI does and decodes it the way
// a standalone container does. The accessor's loader rejects any field it does not recognize, so a
// conversion that emitted a key the mounted config has no home for would take the node down at
// startup rather than showing up here — this closes that loop in a unit test.
func TestConvertedConfigLoadsStrictly(t *testing.T) {
	t.Parallel()

	converted, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
FinalityTagEnabled = false
FinalityDepth = 15
[EVM.Transactions.TransactionManagerV2]
BlockTime = '3s'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
WSURL = 'wss://sepolia.example.com'
[[EVM.Nodes]]
Name = 'backup'
HTTPURL = 'https://sepolia-backup.example.com'
`))
	require.NoError(t, err)

	encoded, err := toml.Marshal(converted.Config)
	require.NoError(t, err)
	t.Logf("converted config:\n%s", encoded)

	var reloaded Config
	md, err := toml.Decode(string(encoded), &reloaded)
	require.NoError(t, err)
	require.Empty(t, md.Undecoded(), "the standalone loader rejects unknown fields")
	assert.Equal(t, converted.Config, reloaded, "the config must survive the encode/decode the CLI and container perform")
}

func TestConvertChainlinkNodeConfigErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name:    "no EVM sections",
			config:  "[Log]\nLevel = 'info'\n",
			wantErr: "no [[EVM]] sections",
		},
		{
			name:    "missing chain ID",
			config:  "[[EVM]]\nFinalityDepth = 5\n",
			wantErr: "no ChainID",
		},
		{
			name: "unknown chain ID",
			config: `
[[EVM]]
ChainID = '88888888888888'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://example.com'
`,
			wantErr: "no known chain selector",
		},
		{
			name:    "chain with no nodes",
			config:  "[[EVM]]\nChainID = '" + sepoliaChainID + "'\n",
			wantErr: "no [[EVM.Nodes]] entries",
		},
		{
			name: "node without an HTTP URL",
			config: `
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'ws-only'
WSURL = 'wss://sepolia.example.com'
`,
			wantErr: "no HTTPURL",
		},
		{
			name: "every node dropped",
			config: `
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'broadcast-only'
HTTPURL = 'https://sepolia.example.com'
SendOnly = true
`,
			wantErr: "no usable [[EVM.Nodes]] entries",
		},
		{
			name: "all chains disabled",
			config: `
[[EVM]]
ChainID = '` + sepoliaChainID + `'
Enabled = false
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`,
			wantErr: "no enabled EVM chains",
		},
		{
			name:    "malformed TOML",
			config:  "[[EVM]\nChainID = 'x'\n",
			wantErr: "failed to parse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := convertChainlinkNodeConfig([]byte(tt.config))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// sepoliaDefaultFinalityDepth is the depth the conversion must emit for a Sepolia chain whose
// finality settings the operator left unset: zero if the node defaults Sepolia to finality tags,
// the default confirmation depth otherwise. It is read from chainlink-evm's own defaults rather
// than hard-coded, so a dependency bump that changes them moves the expectation with the behavior.
//
// The bug it guards against is a conversion that reads only the explicitly set fields: that would
// emit a zero depth — finality-tag mode — for every chain the operator did not configure, silently
// moving a confirmation-depth chain onto tags.
func sepoliaDefaultFinalityDepth(t *testing.T) uint32 {
	t.Helper()
	defaults := evmtoml.Defaults(sqlutil.New(big.NewInt(11155111)))
	if defaults.FinalityTagEnabled != nil && *defaults.FinalityTagEnabled {
		t.Log("chainlink-evm defaults Sepolia to finality tags; expecting a zero depth")
		return 0
	}
	require.NotNil(t, defaults.FinalityDepth, "a chain not on finality tags must have a default depth")
	t.Logf("chainlink-evm defaults Sepolia to confirmation depth %d", *defaults.FinalityDepth)
	return *defaults.FinalityDepth
}
