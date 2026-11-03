package evmconfig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
)

// buildConverted converts a one-chain node config and builds that chain the way a standalone process
// does with the node's TOML mounted.
func buildConverted(t *testing.T, nodeTOML string) (*evmtoml.EVMConfig, Conversion) {
	t.Helper()
	conversion, err := convertChainlinkNodeConfig([]byte(nodeTOML))
	require.NoError(t, err)
	infos, err := conversion.Config.ToInfos()
	require.NoError(t, err)
	require.Len(t, infos, 1)
	var built *evmtoml.EVMConfig
	for _, info := range infos {
		built, err = BuildChainlinkEVMTOML(info)
		require.NoError(t, err)
	}
	return built, conversion
}

// Standalone runs the chain-level tuning the CL node ran. Dropping it is not neutral: a lost gas
// limit multiplier, chain type or RPC error pattern is a transaction that fails after the cutover.
func TestBuildChainlinkEVMTOMLCarriesTheNodeChainSettings(t *testing.T) {
	t.Parallel()

	built, conversion := buildConverted(t, `
[[EVM]]
ChainID = '`+sepoliaChainID+`'
FinalizedBlockOffset = 10
NoNewHeadsThreshold = '1m'
[EVM.GasEstimator]
Mode = 'FeeHistory'
LimitMultiplier = '4'
EstimateLimit = true
PriceMax = '120 gwei'
[EVM.NodePool]
PollInterval = '3s'
PollFailureThreshold = 2
SelectionMode = 'PriorityLevel'
[EVM.NodePool.Errors]
NonceTooLow = '(?i)nonce too low'
[EVM.HeadTracker]
HistoryDepth = 300
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
WSURL = 'wss://sepolia.example.com'
Order = 1
`)
	assert.Empty(t, conversion.Warnings, "every setting above carries over")
	assert.Equal(t, uint32(10), *built.FinalizedBlockOffset)
	assert.Equal(t, time.Minute, built.NoNewHeadsThreshold.Duration())
	assert.Equal(t, "FeeHistory", *built.GasEstimator.Mode)
	assert.Equal(t, "4", built.GasEstimator.LimitMultiplier.String())
	assert.True(t, *built.GasEstimator.EstimateLimit)
	assert.Equal(t, "120 gwei", built.GasEstimator.PriceMax.String())
	assert.Equal(t, 3*time.Second, built.NodePool.PollInterval.Duration())
	assert.Equal(t, uint32(2), *built.NodePool.PollFailureThreshold)
	assert.Equal(t, "PriorityLevel", *built.NodePool.SelectionMode, "Order means something only with PriorityLevel")
	assert.Equal(t, "(?i)nonce too low", *built.NodePool.Errors.NonceTooLow)
	assert.Equal(t, uint32(300), *built.HeadTracker.HistoryDepth)
}

// Whatever the node config says, the built config holds every value the standalone runtime needs.
func TestBuildChainlinkEVMTOMLKeepsWhatStandaloneFixes(t *testing.T) {
	t.Parallel()

	built, _ := buildConverted(t, `
[[EVM]]
ChainID = '`+sepoliaChainID+`'
LogBroadcasterEnabled = true
[EVM.BalanceMonitor]
Enabled = true
[EVM.HeadTracker]
PersistenceEnabled = true
[EVM.Transactions]
Enabled = false
ForwardersEnabled = true
[EVM.Transactions.TransactionManagerV2]
Enabled = false
DualBroadcast = true
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`)
	for _, setting := range standaloneSettings {
		value := *setting.field(&built.Chain)
		require.NotNil(t, value, setting.path)
		assert.Equal(t, setting.value, *value, setting.path)
	}
}

// TXM v2 detects stuck transactions by Threshold alone and refuses AutoPurge without one (newTxmV2),
// which would leave the chain unable to transmit. AutoPurge with a Threshold stays on.
func TestBuildChainlinkEVMTOMLTurnsOffAutoPurgeWithoutAThreshold(t *testing.T) {
	t.Parallel()

	detectionOnly, conversion := buildConverted(t, `
[[EVM]]
ChainID = '`+sepoliaChainID+`'
[EVM.Transactions.AutoPurge]
Enabled = true
DetectionApiUrl = 'https://detect.example.com'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`)
	assert.False(t, *detectionOnly.Transactions.AutoPurge.Enabled)
	assert.Equal(t, []string{
		"chain " + sepoliaChainID + ": turned off Transactions.AutoPurge: TXM v2 detects stuck transactions by " +
			"Transactions.AutoPurge.Threshold alone, and it is missing or zero",
	}, conversion.Warnings)

	zeroThreshold, conversion := buildConverted(t, `
[[EVM]]
ChainID = '`+sepoliaChainID+`'
[EVM.Transactions.AutoPurge]
Enabled = true
Threshold = 0
MinAttempts = 3
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`)
	assert.False(t, *zeroThreshold.Transactions.AutoPurge.Enabled)
	assert.Equal(t, []string{
		"chain " + sepoliaChainID + ": turned off Transactions.AutoPurge: TXM v2 detects stuck transactions by " +
			"Transactions.AutoPurge.Threshold alone, and it is missing or zero",
	}, conversion.Warnings)

	withThreshold, conversion := buildConverted(t, `
[[EVM]]
ChainID = '`+sepoliaChainID+`'
[EVM.Transactions.AutoPurge]
Enabled = true
Threshold = 50
MinAttempts = 3
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`)
	assert.True(t, *withThreshold.Transactions.AutoPurge.Enabled)
	assert.Empty(t, conversion.Warnings)
}

// HTTP-only pools need head polling; an explicit interval from the node config is kept, and only an
// unset one takes the standalone default.
func TestBuildChainlinkEVMTOMLKeepsAnExplicitNewHeadsPollInterval(t *testing.T) {
	t.Parallel()

	explicit, _ := buildConverted(t, `
[[EVM]]
ChainID = '`+sepoliaChainID+`'
[EVM.NodePool]
NewHeadsPollInterval = '4s'
[[EVM.Nodes]]
Name = 'http-only'
HTTPURL = 'https://sepolia.example.com'
`)
	assert.Equal(t, 4*time.Second, explicit.NodePool.NewHeadsPollInterval.Duration())

	unset, _ := buildConverted(t, `
[[EVM]]
ChainID = '`+sepoliaChainID+`'
[[EVM.Nodes]]
Name = 'http-only'
HTTPURL = 'https://sepolia.example.com'
`)
	assert.Equal(t, DefaultNewHeadsPollInterval, unset.NodePool.NewHeadsPollInterval.Duration())
}

// Every chain chainlink-evm has defaults for builds, and none leaves TXM v2 a setting newTxmV2
// rejects. Scroll's defaults enable AutoPurge through a detection API, which once blocked transmission.
func TestBuildChainlinkEVMTOMLGivesEveryKnownChainARunnableTXM(t *testing.T) {
	t.Parallel()

	nodes := []Node{{Name: "primary", HTTPUrl: "http://node.internal:8545", WSUrl: "ws://node.internal:8546"}}
	for _, id := range evmtoml.DefaultIDs {
		built, err := BuildChainlinkEVMTOML(Info{ChainID: id.String(), Nodes: nodes})
		require.NoError(t, err, "chain %s", id)
		assert.False(t, autoPurgeWithoutThreshold(&built.Chain), "chain %s: AutoPurge without a Threshold", id)
		assert.False(t, *built.Transactions.ForwardersEnabled, "chain %s", id)
		assert.False(t, *built.Transactions.TransactionManagerV2.DualBroadcast, "chain %s", id)
		assert.NotNil(t, built.Transactions.TransactionManagerV2.BlockTime, "chain %s", id)
	}
}

func TestToChainlinkEVMNodeMapsOnlyFocusedStandaloneSubset(t *testing.T) {
	t.Parallel()

	info := Info{
		ChainID: "1337",
		Nodes: []Node{{
			Name:    "local-rpc",
			HTTPUrl: "http://node.internal:8545",
			WSUrl:   "ws://node.internal:8546",
		}},
	}

	node, usesPolling, err := toChainlinkEVMNode(info, 0, info.Nodes[0])
	require.NoError(t, err)
	require.False(t, usesPolling)
	require.Equal(t, "local-rpc", *node.Name)
	require.Equal(t, "http://node.internal:8545", node.HTTPURL.String())
	require.Equal(t, "ws://node.internal:8546", node.WSURL.String())
	require.Nil(t, node.HTTPURLExtraWrite)
	require.Nil(t, node.SendOnly)
	require.Nil(t, node.Order, "an unset Order stays nil so chainlink-evm applies its own default priority")
	require.Nil(t, node.IsLoadBalancedRPC)
}

func TestToChainlinkEVMNodeCarriesSelectionPriority(t *testing.T) {
	t.Parallel()

	info := Info{
		ChainID: "1337",
		Nodes: []Node{{
			Name:    "primary",
			HTTPUrl: "http://node.internal:8545",
			Order:   5,
		}},
	}

	node, _, err := toChainlinkEVMNode(info, 0, info.Nodes[0])
	require.NoError(t, err)
	require.NotNil(t, node.Order, "a configured Order must reach the chainlink-evm node")
	require.Equal(t, int32(5), *node.Order)
}

// The three sources of a chain's TXM v2 block time: the operator's explicit value always wins,
// then the curated per-chain default, then the generic 2s fallback.
func TestResolveTXMBlockTime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		info       Info
		want       time.Duration
		wantSource TXMBlockTimeSource
	}{
		{
			name:       "an explicit operator value wins over the curated table",
			info:       Info{ChainID: "1", TXMBlockTime: 7 * time.Second},
			want:       7 * time.Second,
			wantSource: TXMBlockTimeOperator,
		},
		{
			name:       "ethereum mainnet uses the curated 12s",
			info:       Info{ChainID: "1"},
			want:       12 * time.Second,
			wantSource: TXMBlockTimeCuratedDefault,
		},
		{
			name:       "sepolia uses the curated 12s",
			info:       Info{ChainID: sepoliaChainID},
			want:       12 * time.Second,
			wantSource: TXMBlockTimeCuratedDefault,
		},
		{
			name:       "rootstock uses the curated 30s",
			info:       Info{ChainID: "30"},
			want:       30 * time.Second,
			wantSource: TXMBlockTimeCuratedDefault,
		},
		{
			// Arbitrum Sepolia's real block interval is far below the 2s floor upstream
			// validation enforces, so it is deliberately absent from the curated table: the
			// generic fallback is already its best legal value.
			name:       "a chain with no curated entry gets the generic fallback",
			info:       Info{ChainID: arbSepChainID},
			want:       DefaultTXMBlockTime,
			wantSource: TXMBlockTimeGenericFallback,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, source := ResolveTXMBlockTime(tt.info)
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantSource, source)
		})
	}
}

// Every curated value must respect the floor upstream validation enforces (BlockTime >= 2s when
// TXM v2 is enabled): a faster chain added here would fail config validation at build time, which
// is exactly why the table holds only chains slower than the generic fallback.
func TestCuratedTXMBlockTimesRespectTheUpstreamFloor(t *testing.T) {
	t.Parallel()

	for chainID, blockTime := range curatedTXMBlockTimeByChainID {
		require.GreaterOrEqual(t, blockTime, DefaultTXMBlockTime,
			"chain %s: curated values below the 2s validation floor fail upstream validation", chainID)
	}
}

// The resolved value is what actually lands in the chainlink-evm config the runtime builds.
func TestBuildChainlinkEVMTOMLAppliesTheResolvedBlockTime(t *testing.T) {
	t.Parallel()

	nodes := []Node{{Name: "primary", HTTPUrl: "http://node.internal:8545"}}

	curated, err := BuildChainlinkEVMTOML(Info{ChainID: "1", Nodes: nodes})
	require.NoError(t, err)
	require.Equal(t, 12*time.Second, curated.Transactions.TransactionManagerV2.BlockTime.Duration(),
		"ethereum mainnet with no operator value runs the curated 12s")

	override, err := BuildChainlinkEVMTOML(Info{ChainID: "1", TXMBlockTime: 20 * time.Second, Nodes: nodes})
	require.NoError(t, err)
	require.Equal(t, 20*time.Second, override.Transactions.TransactionManagerV2.BlockTime.Duration(),
		"an explicit value wins over the curated default")

	fallback, err := BuildChainlinkEVMTOML(Info{ChainID: arbSepChainID, Nodes: nodes})
	require.NoError(t, err)
	require.Equal(t, DefaultTXMBlockTime, fallback.Transactions.TransactionManagerV2.BlockTime.Duration(),
		"a chain without a curated entry runs the generic fallback")
}

// A negative block time is a config error, not a panic: MustNewDuration panics on negatives, so
// the guard must fire first. The standalone-format decode (a raw time.Duration) is the path that
// can carry one in; the node-config decode rejects negatives already.
func TestBuildChainlinkEVMTOMLRejectsANegativeBlockTime(t *testing.T) {
	t.Parallel()

	_, err := BuildChainlinkEVMTOML(Info{
		ChainID:      "1337",
		TXMBlockTime: -1 * time.Second,
		Nodes:        []Node{{HTTPUrl: "http://node.internal:8545"}},
	})
	require.ErrorContains(t, err, "negative txm_block_time")
}
