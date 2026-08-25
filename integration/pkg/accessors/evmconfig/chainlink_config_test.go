package evmconfig

import (
	"testing"

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
