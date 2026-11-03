package evmconfig

import (
	"math/big"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
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
IsLoadBalancedRPC = true
`))
		require.NoError(t, err)
		require.Len(t, got.Warnings, 1)
		assert.Contains(t, got.Warnings[0], "IsLoadBalancedRPC")
		assert.Len(t, got.Config.Chains[sepoliaSelector].Nodes, 1)
	})

	t.Run("carries chain-level settings over without warning", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[EVM.GasEstimator]
Mode = 'BlockHistory'
[EVM.HeadTracker]
HistoryDepth = 100
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`))
		require.NoError(t, err)
		assert.Empty(t, got.Warnings, "settings standalone runs as written are not deviations")
		carried := got.Config.Chains[sepoliaSelector].chainlinkEVM
		require.NotNil(t, carried)
		assert.Equal(t, "BlockHistory", *carried.GasEstimator.Mode)
		assert.Equal(t, uint32(100), *carried.HeadTracker.HistoryDepth)
	})

	t.Run("carried-over or unset chain-level settings produce no dropped-settings warning", func(t *testing.T) {
		t.Parallel()
		onlyBlockTime, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[EVM.Transactions.TransactionManagerV2]
BlockTime = '7s'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`))
		require.NoError(t, err)
		assert.Empty(t, onlyBlockTime.Warnings, "the TXM block time carries over, so nothing was dropped")

		nothingExtra, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`))
		require.NoError(t, err)
		assert.Empty(t, nothingExtra.Warnings)
	})

	t.Run("carries over per-node Order as the selection priority", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
Order = 50

[[EVM.Nodes]]
Name = 'backup'
HTTPURL = 'https://sepolia-backup.example.com'
`))
		require.NoError(t, err)
		assert.Empty(t, got.Warnings, "Order is a supported setting, not a dropped one")
		nodes := got.Config.Chains[sepoliaSelector].Nodes
		require.Len(t, nodes, 2)
		assert.Equal(t, int32(50), nodes[0].Order, "the node's Order carries over unchanged")
		assert.Equal(t, int32(0), nodes[1].Order, "a node with no Order stays unprioritized")
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
		assert.Equal(t, []string{sepoliaChainID}, got.DisabledChains,
			"a disabled chain is an explicit choice, reported apart from conversion failures")
		assert.Empty(t, got.FailedChains)
	})
}

// Warnings come out in the order the operator wrote the config, so an operator reading the startup
// log walks their own file top to bottom: chains and nodes follow file order, while the dropped
// settings within one chain or node come out sorted. The chains and nodes below are deliberately in
// the opposite order to what sorting would produce: arbitrum-sepolia precedes sepolia though
// "11155111" sorts before "421614", and node zeta precedes node alpha. Node zeta also sets Order, a
// supported setting, to prove it never enters the warning stream.
func TestConvertChainlinkNodeConfigWarningsFollowOperatorOrder(t *testing.T) {
	t.Parallel()

	got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + arbSepChainID + `'
[[EVM.Nodes]]
Name = 'zeta'
HTTPURL = 'https://arb-zeta.example.com'
Order = 50
HTTPURLExtraWrite = 'https://arb-zeta-write.example.com'
IsLoadBalancedRPC = true

[[EVM.Nodes]]
Name = 'alpha'
HTTPURL = 'https://arb-alpha.example.com'
SendOnly = true

[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
HTTPURLExtraWrite = 'https://sepolia-write.example.com'
`))
	require.NoError(t, err)

	require.Equal(t, []string{
		"chain " + arbSepChainID + " node zeta: dropped HTTPURLExtraWrite, standalone CCV does not expose it",
		"chain " + arbSepChainID + " node zeta: dropped IsLoadBalancedRPC, standalone CCV does not expose it",
		"chain " + arbSepChainID + " node alpha: dropped, SendOnly nodes have no standalone equivalent",
		"chain " + sepoliaChainID + " node primary: dropped HTTPURLExtraWrite, standalone CCV does not expose it",
	}, got.Warnings)
	assert.Equal(t, int32(50), got.Config.Chains[arbSepSelector].Nodes[0].Order,
		"Order is carried, not warned about")

	// The grouped view carries the same warnings, so a per-chain report (`ccv migrate
	// inspect-config --chain-selector`) narrows them without parsing the message text.
	assert.Equal(t, map[string][]string{
		arbSepChainID: {
			"chain " + arbSepChainID + " node zeta: dropped HTTPURLExtraWrite, standalone CCV does not expose it",
			"chain " + arbSepChainID + " node zeta: dropped IsLoadBalancedRPC, standalone CCV does not expose it",
			"chain " + arbSepChainID + " node alpha: dropped, SendOnly nodes have no standalone equivalent",
		},
		sepoliaChainID: {
			"chain " + sepoliaChainID + " node primary: dropped HTTPURLExtraWrite, standalone CCV does not expose it",
		},
	}, got.WarningsByChainID)
}

// Set-detection reads the operator's file rather than the decoded chainlink-evm struct, so it
// names settings the typed config has no field for: options a newer node version added, and typos
// of real ones. Those are the only chain-level settings that cannot carry over — a typo of
// FinalityDepth silently reverting to the chain default is the case this guards.
func TestConvertChainlinkNodeConfigWarnsAboutSettingsUnknownToTheTypedConfig(t *testing.T) {
	t.Parallel()

	got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
FinalityDepht = 22
[EVM.GasEstimator]
Mode = 'BlockHistory'
FutureEstimatorSetting = 'x'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
FutureNodeSetting = true
`))
	require.NoError(t, err)
	require.Equal(t, []string{
		"chain " + sepoliaChainID + ": dropped set chain-level settings unknown to this release: " +
			"FinalityDepht, GasEstimator.FutureEstimatorSetting",
		"chain " + sepoliaChainID + " node primary: dropped FutureNodeSetting, standalone CCV does not expose it",
	}, got.Warnings, "GasEstimator.Mode is a known setting, so it carries over rather than being named")
}

// A node config can set what the standalone runtime has no other mode for; standalone keeps its own
// value and names each one that differs. A setting written with standalone's own value is not named.
func TestConvertChainlinkNodeConfigNamesSettingsStandaloneFixes(t *testing.T) {
	t.Parallel()

	got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
LogBroadcasterEnabled = true
[EVM.BalanceMonitor]
Enabled = true
[EVM.HeadTracker]
PersistenceEnabled = true
[EVM.Transactions]
ForwardersEnabled = false
[EVM.Transactions.TransactionManagerV2]
DualBroadcast = true
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`))
	require.NoError(t, err)
	require.Equal(t, []string{
		"chain " + sepoliaChainID + ": standalone sets these itself, overriding the node config: " +
			"BalanceMonitor.Enabled = false, HeadTracker.PersistenceEnabled = false, LogBroadcasterEnabled = false, " +
			"Transactions.TransactionManagerV2.DualBroadcast = false",
	}, got.Warnings)
}

// A value this release cannot decode costs that value, not the file: the rest of the chain's
// settings, its nodes, and every other chain still convert. Some decode errors name their key and
// some (a duration without a unit) do not, so both kinds are here.
func TestConvertChainlinkNodeConfigDropsValuesItCannotDecode(t *testing.T) {
	t.Parallel()

	got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = 'not-a-number'
[[EVM.Nodes]]
Name = 'lost'
HTTPURL = 'https://lost.example.com'

[[EVM]]
ChainID = '` + sepoliaChainID + `'
[EVM.GasEstimator]
PriceMax = 'lots'
LimitMultiplier = '4'
[EVM.NodePool]
PollInterval = 3
PollFailureThreshold = 2
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
Order = 'first'

[[EVM]]
ChainID = '` + arbSepChainID + `'
[[EVM.Nodes]]
Name = 'arb'
HTTPURL = 'https://arb.example.com'
`))
	require.NoError(t, err)
	require.Equal(t, []string{
		"[[EVM]] entry 0: skipped, its ChainID does not decode",
		"chain " + sepoliaChainID + ": dropped set settings this release cannot decode: " +
			"GasEstimator.PriceMax, NodePool.PollInterval, Nodes[0].Order",
	}, got.Warnings)
	require.Len(t, got.Config.Chains, 2, "both decodable chains convert")

	sepolia := got.Config.Chains[sepoliaSelector]
	assert.Equal(t, "4", sepolia.chainlinkEVM.GasEstimator.LimitMultiplier.String())
	assert.Equal(t, uint32(2), *sepolia.chainlinkEVM.NodePool.PollFailureThreshold)
	assert.Nil(t, sepolia.chainlinkEVM.GasEstimator.PriceMax)
	require.Len(t, sepolia.Nodes, 1)
	assert.Equal(t, Node{Name: "primary", HTTPUrl: "https://sepolia.example.com"}, sepolia.Nodes[0],
		"the node survives without its undecodable Order")
}

// A setting that decodes but fails this release's chainlink-evm validation (a node on a newer
// chainlink-evm can hold one) is dropped by name; the chain keeps the rest and still builds.
func TestConvertChainlinkNodeConfigDropsSettingsValidationRejects(t *testing.T) {
	t.Parallel()

	got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
ChainType = 'chain-from-the-future'
[EVM.GasEstimator]
LimitMultiplier = '4'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`))
	require.NoError(t, err)
	require.Len(t, got.Warnings, 1)
	assert.Contains(t, got.Warnings[0], "chain "+sepoliaChainID+": dropped chain-level settings this release rejects: ChainType (")
	carried := got.Config.Chains[sepoliaSelector].chainlinkEVM
	assert.Nil(t, carried.ChainType)
	assert.Equal(t, "4", carried.GasEstimator.LimitMultiplier.String())

	infos, err := got.Config.ToInfos()
	require.NoError(t, err)
	_, err = BuildChainlinkEVMTOML(infos[sepoliaSelector])
	require.NoError(t, err, "the chain builds with what was kept")
}

// KeySpecific entries are keyed to the node's own addresses. The standalone executor transmits from
// a key it generates, so the entries cannot match anything and are dropped by name.
func TestConvertChainlinkNodeConfigDropsKeySpecific(t *testing.T) {
	t.Parallel()

	got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.KeySpecific]]
Key = '0x2a3e23c6f242F5345320814aC8a1b4E58707D292'
GasEstimator.PriceMax = '79 gwei'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`))
	require.NoError(t, err)
	require.Equal(t, []string{
		"chain " + sepoliaChainID + ": dropped KeySpecific: its entries name the node's own keys, and the " +
			"standalone executor transmits from a new one",
	}, got.Warnings)
	assert.Empty(t, got.Config.Chains[sepoliaSelector].chainlinkEVM.KeySpecific)
}

// A dropped node takes its settings with it, and the migration guide promises every dropped
// per-node setting is named at startup. The node-level drop carries them rather than emitting a
// line per setting, which would read as though the node survived without them.
func TestConvertChainlinkNodeConfigNamesSettingsDroppedWithASendOnlyNode(t *testing.T) {
	t.Parallel()

	got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
[[EVM.Nodes]]
Name = 'broadcast'
HTTPURL = 'https://sepolia-send.example.com'
SendOnly = true
HTTPURLExtraWrite = 'https://sepolia-extra.example.com'
FutureNodeSetting = true
`))
	require.NoError(t, err)
	require.Equal(t, []string{
		"chain " + sepoliaChainID + " node broadcast: dropped, SendOnly nodes have no standalone " +
			"equivalent (FutureNodeSetting, HTTPURLExtraWrite dropped with it)",
	}, got.Warnings)
	require.Len(t, got.Config.Chains[sepoliaSelector].Nodes, 1, "only the full node is carried")
}

// Everything outside [[EVM]] is ignored by design — but named, not silent: the conversion lists
// the top-level sections it did not read so the pre-cutover review sees them.
func TestConvertChainlinkNodeConfigNamesIgnoredTopLevelSections(t *testing.T) {
	t.Parallel()

	got, err := convertChainlinkNodeConfig([]byte(`
[Log]
Level = 'debug'

[Database]
URL = 'postgresql://localhost:5432/chainlink'

[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'

[WebServer]
HTTPPort = 6688
`))
	require.NoError(t, err)
	assert.Equal(t, []string{"Database", "Log", "WebServer"}, got.IgnoredSections)
	assert.Empty(t, got.Warnings, "a config that sets nothing extra has no drops to warn about")
}

// A setting written in an earlier [[EVM]] block for the chain is still set after the blocks merge:
// later blocks override but never un-set, so the carried settings and the warnings both union the
// blocks. This is the shape of a node config split into a chains file and an RPCs file.
func TestConvertChainlinkNodeConfigMergesSettingsFromEveryBlock(t *testing.T) {
	t.Parallel()

	got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[EVM.HeadTracker]
HistoryDepth = 100
HistoryDept = 5
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'

[[EVM]]
ChainID = '` + sepoliaChainID + `'
FinalityDepth = 99
`))
	require.NoError(t, err)
	require.Equal(t, []string{
		"chain " + sepoliaChainID + ": dropped set chain-level settings unknown to this release: HeadTracker.HistoryDept",
	}, got.Warnings)
	carried := got.Config.Chains[sepoliaSelector].chainlinkEVM
	assert.Equal(t, uint32(100), *carried.HeadTracker.HistoryDepth, "the first block's setting survives the merge")
	assert.Equal(t, uint32(99), *carried.FinalityDepth)
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
Order = 10
[[EVM.Nodes]]
Name = 'backup'
HTTPURL = 'https://sepolia-backup.example.com'
`))
	require.NoError(t, err)
	require.Equal(t, int32(10), converted.Config.Chains[sepoliaSelector].Nodes[0].Order,
		"a converted Order must reach the encode/decode round-trip below")

	encoded, err := toml.Marshal(converted.Config)
	require.NoError(t, err)
	t.Logf("converted config:\n%s", encoded)

	var reloaded Config
	md, err := toml.Decode(string(encoded), &reloaded)
	require.NoError(t, err)
	require.Empty(t, md.Undecoded(), "the standalone loader rejects unknown fields")

	// The node's chain-level settings ride in memory only: the standalone format has no field for them.
	want := Config{Chains: make(map[string]ChainConfig, len(converted.Config.Chains))}
	for selector, chain := range converted.Config.Chains {
		require.NotNil(t, chain.chainlinkEVM)
		chain.chainlinkEVM = nil
		want.Chains[selector] = chain
	}
	assert.Equal(t, want, reloaded, "the config must survive the encode/decode the CLI and container perform")
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

// A chain that cannot run standalone is skipped, not fatal: the reason is recorded in
// FailedChains and warned about, and the remaining chains convert. The leftover [[EVM]] block for a
// chain whose RPC was decommissioned — or a typo'd chain ID — must not take down the config for
// the chains that are fine. Whether a skip is acceptable is the bootstrapper's call: it refuses to
// boot when the skipped chain is one the operator declared in [[chains]].
func TestConvertChainlinkNodeConfigSkipsUnservableChains(t *testing.T) {
	t.Parallel()

	t.Run("an unknown chain ID skips, the rest convert", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '88888888888888'
[[EVM.Nodes]]
Name = 'mystery'
HTTPURL = 'https://mystery.example.com'

[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`))
		require.NoError(t, err)
		assert.Len(t, got.Config.Chains, 1)
		assert.Contains(t, got.Config.Chains, sepoliaSelector)

		require.Len(t, got.FailedChains, 1)
		assert.Equal(t, "88888888888888", got.FailedChains[0].ChainID)
		assert.Contains(t, got.FailedChains[0].Reason, "no known chain selector")

		require.Len(t, got.Warnings, 1, "the failed chain's only warning is the skip line")
		assert.Equal(t, "chain 88888888888888: skipped, "+got.FailedChains[0].Reason, got.Warnings[0])
		assert.Equal(t, got.Warnings, got.WarningsByChainID["88888888888888"],
			"the grouped view carries the same skip line")
	})

	t.Run("a node without an HTTP URL skips only its own chain", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'

[[EVM]]
ChainID = '` + arbSepChainID + `'
[[EVM.Nodes]]
Name = 'ws-only'
WSURL = 'wss://arb.example.com'
`))
		require.NoError(t, err)
		assert.Len(t, got.Config.Chains, 1)
		assert.Contains(t, got.Config.Chains, sepoliaSelector)

		require.Len(t, got.FailedChains, 1)
		assert.Equal(t, arbSepChainID, got.FailedChains[0].ChainID)
		assert.Contains(t, got.FailedChains[0].Reason, "node ws-only has no HTTPURL")
		assert.Contains(t, got.FailedChains[0].Reason, "standalone CCV requires an HTTP endpoint")

		require.Equal(t, []string{
			"chain " + arbSepChainID + ": skipped, node ws-only has no HTTPURL; standalone CCV requires an HTTP endpoint for every node",
		}, got.Warnings)
	})

	t.Run("a chain with no nodes and a send-only pool both skip", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'

[[EVM]]
ChainID = '` + arbSepChainID + `'
[[EVM.Nodes]]
Name = 'broadcast-only'
HTTPURL = 'https://arb.example.com'
SendOnly = true

[[EVM]]
ChainID = '1'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://eth.example.com'
`))
		require.NoError(t, err)
		require.Len(t, got.Config.Chains, 1)
		assert.Contains(t, got.Config.Chains, "5009297550715157269", "the healthy ethereum-mainnet chain converts")
		require.Len(t, got.FailedChains, 2)
		assert.Equal(t, sepoliaChainID, got.FailedChains[0].ChainID)
		assert.Contains(t, got.FailedChains[0].Reason, "has no [[EVM.Nodes]] entries")
		assert.Equal(t, arbSepChainID, got.FailedChains[1].ChainID)
		assert.Contains(t, got.FailedChains[1].Reason, "has no usable [[EVM.Nodes]] entries after conversion")
	})

	t.Run("every enabled chain failing is an error naming all of them", func(t *testing.T) {
		t.Parallel()
		_, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '88888888888888'
[[EVM.Nodes]]
Name = 'mystery'
HTTPURL = 'https://mystery.example.com'

[[EVM]]
ChainID = '` + sepoliaChainID + `'
`))
		require.ErrorContains(t, err, "config has no usable EVM chains")
		require.ErrorContains(t, err, "chain 88888888888888 its chain ID has no known chain selector")
		require.ErrorContains(t, err, "chain "+sepoliaChainID+" has no [[EVM.Nodes]] entries")
	})

	t.Run("disabled and failing chains coexist with a healthy one", func(t *testing.T) {
		t.Parallel()
		got, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
Enabled = false
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'

[[EVM]]
ChainID = '88888888888888'
[[EVM.Nodes]]
Name = 'mystery'
HTTPURL = 'https://mystery.example.com'

[[EVM]]
ChainID = '` + arbSepChainID + `'
[[EVM.Nodes]]
Name = 'arb'
HTTPURL = 'https://arb.example.com'
`))
		require.NoError(t, err)
		assert.Len(t, got.Config.Chains, 1)
		assert.Contains(t, got.Config.Chains, arbSepSelector)

		require.Len(t, got.FailedChains, 1)
		assert.Equal(t, "88888888888888", got.FailedChains[0].ChainID)
		assert.Equal(t, []string{sepoliaChainID}, got.DisabledChains)

		require.Len(t, got.Warnings, 2)
		assert.Contains(t, got.Warnings[0], "chain "+sepoliaChainID+": skipped, the node has it disabled")
		assert.Contains(t, got.Warnings[1], "chain 88888888888888: skipped, its chain ID has no known chain selector")
	})
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
	defaults := chainDefaults(sqlutil.New(big.NewInt(11155111)))
	if defaults.FinalityTagEnabled != nil && *defaults.FinalityTagEnabled {
		t.Log("chainlink-evm defaults Sepolia to finality tags; expecting a zero depth")
		return 0
	}
	require.NotNil(t, defaults.FinalityDepth, "a chain not on finality tags must have a default depth")
	t.Logf("chainlink-evm defaults Sepolia to confirmation depth %d", *defaults.FinalityDepth)
	return *defaults.FinalityDepth
}
