package evmconfig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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
