package evm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/config/chaintype"
)

func TestProductionMultiNodeClientUsesHealthyRPCWhenAnotherRPCFails(t *testing.T) {
	t.Parallel()

	failingRPC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "RPC unavailable", http.StatusServiceUnavailable)
	}))
	defer failingRPC.Close()

	healthyRPC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var result any
		switch req.Method {
		case "eth_chainId":
			result = "0x539"
		case "eth_blockNumber":
			result = "0x2a"
		default:
			http.Error(w, "unexpected RPC method: "+req.Method, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  result,
		}); err != nil {
			t.Errorf("encode JSON-RPC response: %v", err)
		}
	}))
	defer healthyRPC.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	chainClient, err := CreateMultiNodeClientFromInfo(ctx, Info{
		ChainID: "1337",
		Nodes: []Node{
			{InternalHTTPUrl: failingRPC.URL},
			{InternalHTTPUrl: healthyRPC.URL},
		},
	}, logger.Test(t))
	require.NoError(t, err)
	defer chainClient.Close()

	height, err := chainClient.LatestBlockHeight(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(42), height.Int64())
}

func TestNewChainlinkEVMConfigUsesProductionDefaultsAndEveryRPCNode(t *testing.T) {
	t.Parallel()

	cfg, err := newChainlinkEVMConfig(Info{
		ChainID:         "42161",
		UniqueChainName: "arbitrum-mainnet",
		Nodes: []Node{
			{
				InternalHTTPUrl: "http://node-a.internal:8545",
				InternalWSUrl:   "ws://node-a.internal:8546",
			},
			{
				InternalHTTPUrl: "http://node-b.internal:8545",
				InternalWSUrl:   "ws://node-b.internal:8546",
			},
		},
	})
	require.NoError(t, err)

	require.Equal(t, chaintype.ChainArbitrum, cfg.EVM().ChainType(), "known-chain defaults must be preserved")
	require.Equal(t, "HighestHead", cfg.EVM().NodePool().SelectionMode())
	require.Equal(t, uint32(vtypes.ConfirmationDepth), cfg.EVM().FinalityDepth())
	require.False(t, cfg.EVM().HeadTracker().PersistenceEnabled())
	require.True(t, cfg.EVM().Transactions().Enabled())
	require.False(t, cfg.EVM().Transactions().ForwardersEnabled())
	require.True(t, cfg.EVM().Transactions().TransactionManagerV2().Enabled())
	require.Equal(t, defaultTXMBlockTime, *cfg.EVM().Transactions().TransactionManagerV2().BlockTime())

	nodes := cfg.Nodes()
	require.Len(t, nodes, 2)
	require.Equal(t, "arbitrum-mainnet-1", *nodes[0].Name)
	require.Equal(t, "http://node-a.internal:8545", nodes[0].HTTPURL.String())
	require.Equal(t, "ws://node-a.internal:8546", nodes[0].WSURL.String())
	require.Equal(t, "arbitrum-mainnet-2", *nodes[1].Name)
	require.Equal(t, "http://node-b.internal:8545", nodes[1].HTTPURL.String())
	require.Equal(t, "ws://node-b.internal:8546", nodes[1].WSURL.String())
}

func TestToChainlinkEVMNodeMapsOnlyFocusedStandaloneSubset(t *testing.T) {
	t.Parallel()

	info := Info{
		ChainID:         "1337",
		UniqueChainName: "local-chain",
		Nodes: []Node{{
			ExternalHTTPUrl: "https://external.example.test",
			InternalHTTPUrl: "http://node.internal:8545",
			ExternalWSUrl:   "wss://external.example.test",
			InternalWSUrl:   "ws://node.internal:8546",
		}},
	}

	node, usesPolling, err := toChainlinkEVMNode(info, 0, info.Nodes[0])
	require.NoError(t, err)
	require.False(t, usesPolling)
	require.Equal(t, "local-chain", *node.Name)
	require.Equal(t, "http://node.internal:8545", node.HTTPURL.String())
	require.Equal(t, "ws://node.internal:8546", node.WSURL.String())
	require.Nil(t, node.HTTPURLExtraWrite)
	require.Nil(t, node.SendOnly)
	require.Nil(t, node.Order)
	require.Nil(t, node.IsLoadBalancedRPC)
}

func TestNewChainlinkEVMConfigSupportsExternalHTTPOnlyRPC(t *testing.T) {
	t.Parallel()

	cfg, err := newChainlinkEVMConfig(Info{
		ChainID: "1337",
		Type:    "anvil",
		Nodes: []Node{{
			ExternalHTTPUrl: "https://rpc.example.test",
		}},
	})
	require.NoError(t, err)

	require.Equal(t, chaintype.ChainType(""), cfg.EVM().ChainType())
	require.Equal(t, defaultNewHeadsPollInterval, cfg.EVM().NodePool().NewHeadsPollInterval())
	require.Len(t, cfg.Nodes(), 1)
	require.Equal(t, "evm-1337", *cfg.Nodes()[0].Name)
	require.Equal(t, "https://rpc.example.test", cfg.Nodes()[0].HTTPURL.String())
	require.Nil(t, cfg.Nodes()[0].WSURL)
}

func TestNewChainlinkEVMConfigRejectsInvalidStandaloneConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		info    Info
		wantErr string
	}{
		{
			name:    "invalid chain ID",
			info:    Info{ChainID: "not-a-number"},
			wantErr: "failed to parse EVM chain ID",
		},
		{
			name:    "no nodes",
			info:    Info{ChainID: "1337"},
			wantErr: "has no RPC nodes",
		},
		{
			name: "node without HTTP RPC",
			info: Info{
				ChainID: "1337",
				Nodes:   []Node{{InternalWSUrl: "ws://node.internal:8546"}},
			},
			wantErr: "has no HTTP RPC URL",
		},
		{
			name: "unsupported chain type",
			info: Info{
				ChainID: "1337",
				Type:    "typo-chain",
				Nodes:   []Node{{InternalHTTPUrl: "http://node.internal:8545"}},
			},
			wantErr: "unsupported EVM chain type",
		},
		{
			name: "invalid HTTP scheme",
			info: Info{
				ChainID: "1337",
				Nodes:   []Node{{InternalHTTPUrl: "ws://node.internal:8545"}},
			},
			wantErr: "invalid chainlink-evm config",
		},
		{
			name: "duplicate RPC endpoint",
			info: Info{
				ChainID: "1337",
				Nodes: []Node{
					{InternalHTTPUrl: "http://node.internal:8545"},
					{InternalHTTPUrl: "http://node.internal:8545"},
				},
			},
			wantErr: "duplicate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := newChainlinkEVMConfig(tt.info)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestNewChainlinkEVMConfigEnablesPollingWhenAnyNodeHasNoWebSocket(t *testing.T) {
	t.Parallel()

	cfg, err := newChainlinkEVMConfig(Info{
		ChainID: "1337",
		Nodes: []Node{
			{InternalHTTPUrl: "http://node-a.internal:8545", InternalWSUrl: "ws://node-a.internal:8546"},
			{InternalHTTPUrl: "http://node-b.internal:8545"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, time.Second, cfg.EVM().NodePool().NewHeadsPollInterval())
}
