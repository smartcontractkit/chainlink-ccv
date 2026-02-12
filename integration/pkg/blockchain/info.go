package blockchain

import (
	"fmt"
	"strconv"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain/canton"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// StellarNetworkInfo contains Stellar network-specific configuration for blockchain info.
type StellarNetworkInfo struct {
	NetworkPassphrase string `json:"network_passphrase"`
	FriendbotURL      string `json:"friendbot_url"`
	SorobanRPCURL     string `json:"soroban_rpc_url"`
}

type NetworkSpecificData struct {
	CantonEndpoints *canton.Endpoints   `json:"canton_endpoints"`
	StellarNetwork  *StellarNetworkInfo `json:"stellar_network"`
}

// Node represents a blockchain node with connection information.
type Node struct {
	ExternalHTTPUrl string `json:"external_http_url"`
	InternalHTTPUrl string `json:"internal_http_url"`
	ExternalWSUrl   string `json:"external_ws_url"`
	InternalWSUrl   string `json:"internal_ws_url"`
}

// Info represents blockchain connection information.
type Info struct {
	ChainID             string               `json:"chain_id"`
	Type                string               `json:"type"`
	Family              string               `json:"family"`
	UniqueChainName     string               `json:"unique_chain_name"`
	Nodes               []*Node              `json:"nodes"`
	NetworkSpecificData *NetworkSpecificData `json:"network_specific_data"`
}

// Helper provides utilities for working with blockchain information.
type Helper struct {
	infos map[string]*Info
}

// NewHelper creates a new blockchain helper with the provided blockchain information.
func NewHelper(infos map[string]*Info) *Helper {
	return &Helper{
		infos: infos,
	}
}

// GetBlockchainByChainID returns the blockchain info for a given chain ID.
func (bh *Helper) GetBlockchainByChainID(chainID string) (*Info, error) {
	for _, info := range bh.infos {
		if info.ChainID == chainID {
			return info, nil
		}
	}
	if info, exists := bh.infos[chainID]; exists {
		return info, nil
	}
	return nil, fmt.Errorf("blockchain with chain ID %s not found", chainID)
}

// GetBlockchainByChainSelector returns the blockchain info for a given chain selector.
func (bh *Helper) GetBlockchainByChainSelector(chainSelector protocol.ChainSelector) (*Info, error) {
	selector := fmt.Sprintf("%d", uint64(chainSelector))
	if info, exists := bh.infos[selector]; exists {
		return info, nil
	}
	return nil, fmt.Errorf("selector %d not found", uint64(chainSelector))
}

// GetRPCEndpoint returns the RPC endpoint for a blockchain by chain selector
// Returns the first available HTTP endpoint.
func (bh *Helper) GetRPCEndpoint(chainSelector protocol.ChainSelector) (string, error) {
	bi, err := bh.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return "", err
	}

	return bi.GetRPCEndpoint()
}

// GetRPCEndpoint returns the RPC endpoint for a blockchain by chain selector
// Returns the first available HTTP endpoint.
func (bi *Info) GetRPCEndpoint() (string, error) {
	if len(bi.Nodes) == 0 {
		return "", fmt.Errorf("no nodes found for chain %s", bi.ChainID)
	}

	if bi.Nodes[0].ExternalHTTPUrl == "" {
		return "", fmt.Errorf("no HTTP URL found for chain %s", bi.ChainID)
	}

	return bi.Nodes[0].ExternalHTTPUrl, nil
}

// GetAllChainSelectors returns all available chain selectors.
func (bh *Helper) GetAllChainSelectors() []protocol.ChainSelector {
	selectors := make([]protocol.ChainSelector, 0)
	for sel := range bh.infos {
		selector, err := strconv.ParseUint(sel, 10, 64)
		if err != nil {
			continue
		}
		selectors = append(selectors, protocol.ChainSelector(selector))
	}
	return selectors
}

// GetBlockchainInfo returns formatted information about a blockchain.
func (bh *Helper) GetBlockchainInfo(chainSelector protocol.ChainSelector) (string, error) {
	info, err := bh.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return "", err
	}

	nodeCount := len(info.Nodes)
	var rpcURL string
	if nodeCount > 0 && info.Nodes[0].ExternalHTTPUrl != "" {
		rpcURL = info.Nodes[0].ExternalHTTPUrl
	} else {
		rpcURL = "N/A"
	}

	return fmt.Sprintf("Chain ID: %s, Type: %s, Family: %s, ChainName: %s, Nodes: %d, RPC: %s, NetworkSpecificData: %+v",
		info.ChainID, info.Type, info.Family, info.UniqueChainName, nodeCount, rpcURL, info.NetworkSpecificData), nil
}

// GetWebSocketEndpoint returns the WebSocket endpoint for a blockchain by chain selector
// Returns the first available WebSocket endpoint.
func (bh *Helper) GetWebSocketEndpoint(chainSelector protocol.ChainSelector) (string, error) {
	bi, err := bh.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return "", err
	}

	return bi.GetWebSocketEndpoint()
}

// GetWebSocketEndpoint returns the WebSocket endpoint for a blockchain by chain selector
// Returns the first available WebSocket endpoint.
func (bi *Info) GetWebSocketEndpoint() (string, error) {
	if len(bi.Nodes) == 0 {
		return "", fmt.Errorf("no nodes found for chain %s", bi.ChainID)
	}

	if bi.Nodes[0].ExternalWSUrl == "" {
		return "", fmt.Errorf("no WebSocket URL found for chain %s", bi.ChainID)
	}

	return bi.Nodes[0].ExternalWSUrl, nil
}

// GetAllNodes returns all nodes for a blockchain by chain selector.
func (bh *Helper) GetAllNodes(chainSelector protocol.ChainSelector) ([]*Node, error) {
	info, err := bh.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return nil, err
	}

	return info.Nodes, nil
}

// GetInternalRPCEndpoint returns the internal RPC endpoint for a blockchain by chain selector
// Useful for container-to-container communication.
func (bh *Helper) GetInternalRPCEndpoint(chainSelector protocol.ChainSelector) (string, error) {
	bi, err := bh.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return "", err
	}

	return bi.GetInternalRPCEndpoint()
}

func (bh *Helper) GetNetworkSpecificData(chainSelector protocol.ChainSelector) (*NetworkSpecificData, error) {
	bi, err := bh.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return nil, err
	}

	return bi.NetworkSpecificData, nil
}

// GetInternalRPCEndpoint returns the internal RPC endpoint for a blockchain by chain selector
// Useful for container-to-container communication.
func (bi *Info) GetInternalRPCEndpoint() (string, error) {
	if len(bi.Nodes) == 0 {
		return "", fmt.Errorf("no nodes found for chain %s", bi.ChainID)
	}

	if bi.Nodes[0].InternalHTTPUrl == "" {
		return "", fmt.Errorf("no internal HTTP URL found for chain %s", bi.ChainID)
	}

	return bi.Nodes[0].InternalHTTPUrl, nil
}

// GetInternalWebsocketEndpoint returns the internal websocket endpoint for a blockchain by chain selector
// Useful for container-to-container communication.
func (bh *Helper) GetInternalWebsocketEndpoint(chainSelector protocol.ChainSelector) (string, error) {
	bi, err := bh.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return "", err
	}

	return bi.GetInternalWebsocketEndpoint()
}

// GetInternalWebsocketEndpoint returns the internal websocket endpoint for a blockchain by chain selector
// Useful for container-to-container communication.
func (bi *Info) GetInternalWebsocketEndpoint() (string, error) {
	if len(bi.Nodes) == 0 {
		return "", fmt.Errorf("no nodes found for chain %s", bi.ChainID)
	}

	if bi.Nodes[0].InternalWSUrl == "" {
		return "", fmt.Errorf("no internal HTTP URL found for chain %s", bi.ChainID)
	}

	return bi.Nodes[0].InternalWSUrl, nil
}
