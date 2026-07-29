package chainconfig

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// Standalone services read the generated config from inside the Docker network, so this boundary
// resolves CTF's host/container endpoint pair down to the container-reachable address. Nodes and
// their endpoints keep the order CTF published them in.
func TestConvertBlockchainOutputsToInfoSelectsContainerReachableEndpoints(t *testing.T) {
	t.Parallel()

	infos, err := ConvertBlockchainOutputsToInfo([]*blockchain.Output{{
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
			},
		},
	}})
	require.NoError(t, err)
	require.Len(t, infos, 1)

	info := infos[selectorOf(t, "1337")]
	require.Equal(t, "1337", info.ChainID)
	require.Len(t, info.Nodes, 2)
	require.Equal(t, "http://evm-node:8545", info.Nodes[0].HTTPUrl)
	require.Equal(t, "ws://evm-node:8546", info.Nodes[0].WSUrl)
	require.Equal(t, "http://evm-node-secondary:8545", info.Nodes[1].HTTPUrl)
	require.Empty(t, info.Nodes[1].WSUrl)
}

// Chains that only exist outside the network, such as a testnet RPC named in an env TOML, publish
// no container-reachable address; that host-facing URL is the only one there is.
func TestConvertBlockchainOutputsToInfoFallsBackToHostEndpoints(t *testing.T) {
	t.Parallel()

	infos, err := ConvertBlockchainOutputsToInfo([]*blockchain.Output{{
		Family:  chainsel.FamilyEVM,
		ChainID: "11155111",
		Nodes: []*blockchain.Node{{
			ExternalHTTPUrl: "https://rpcs.cldev.sh/ethereum/sepolia",
			ExternalWSUrl:   "wss://rpcs.cldev.sh/ethereum/sepolia",
		}},
	}})
	require.NoError(t, err)

	info := infos[selectorOf(t, "11155111")]
	require.Len(t, info.Nodes, 1)
	require.Equal(t, "https://rpcs.cldev.sh/ethereum/sepolia", info.Nodes[0].HTTPUrl)
	require.Equal(t, "wss://rpcs.cldev.sh/ethereum/sepolia", info.Nodes[0].WSUrl)
}

func selectorOf(t *testing.T, chainID string) string {
	t.Helper()
	details, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
	require.NoError(t, err)
	return strconv.FormatUint(details.ChainSelector, 10)
}
