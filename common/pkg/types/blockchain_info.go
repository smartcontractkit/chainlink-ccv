package types

import (
	"fmt"

	protocltypes "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// Node represents a blockchain node with connection information.
type Node struct {
	ExternalHTTPUrl string `json:"external_http_url"`
	InternalHTTPUrl string `json:"internal_http_url"`
	ExternalWSUrl   string `json:"external_ws_url"`
	InternalWSUrl   string `json:"internal_ws_url"`
}

// BlockchainInfo represents blockchain connection information.
type BlockchainInfo struct {
	ChainID       string  `json:"chain_id"`
	Type          string  `json:"type"`
	Family        string  `json:"family"`
	ContainerName string  `json:"container_name"`
	Nodes         []*Node `json:"nodes"`
}

// BlockchainHelper provides utilities for working with blockchain information.
type BlockchainHelper struct {
	blockchainInfos map[string]*BlockchainInfo
}

// NewBlockchainHelper creates a new blockchain helper with the provided blockchain information.
func NewBlockchainHelper(blockchainInfos map[string]*BlockchainInfo) *BlockchainHelper {
	return &BlockchainHelper{
		blockchainInfos: blockchainInfos,
	}
}

// GetBlockchainByChainID returns the blockchain info for a given chain ID.
func (bh *BlockchainHelper) GetBlockchainByChainID(chainID string) (*BlockchainInfo, error) {
	if info, exists := bh.blockchainInfos[chainID]; exists {
		return info, nil
	}
	return nil, fmt.Errorf("blockchain with chain ID %s not found", chainID)
}

// GetBlockchainByChainSelector returns the blockchain info for a given chain selector
// This assumes chain selector maps to chain ID (1337 -> "1337", 2337 -> "2337", etc.)
func (bh *BlockchainHelper) GetBlockchainByChainSelector(chainSelector protocltypes.ChainSelector) (*BlockchainInfo, error) {
	chainID := fmt.Sprintf("%d", uint64(chainSelector))
	return bh.GetBlockchainByChainID(chainID)
}

// GetRPCEndpoint returns the RPC endpoint for a blockchain by chain selector
// Returns the first available HTTP endpoint.
func (bh *BlockchainHelper) GetRPCEndpoint(chainSelector protocltypes.ChainSelector) (string, error) {
	info, err := bh.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return "", err
	}

	if len(info.Nodes) == 0 {
		return "", fmt.Errorf("no nodes found for chain %d", uint64(chainSelector))
	}

	if info.Nodes[0].ExternalHTTPUrl == "" {
		return "", fmt.Errorf("no HTTP URL found for chain %d", uint64(chainSelector))
	}

	return info.Nodes[0].ExternalHTTPUrl, nil
}

// GetAllChainIDs returns all available chain IDs.
func (bh *BlockchainHelper) GetAllChainIDs() []string {
	chainIDs := make([]string, 0, len(bh.blockchainInfos))
	for chainID := range bh.blockchainInfos {
		chainIDs = append(chainIDs, chainID)
	}
	return chainIDs
}

// GetBlockchainInfo returns formatted information about a blockchain.
func (bh *BlockchainHelper) GetBlockchainInfo(chainSelector protocltypes.ChainSelector) (string, error) {
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

	return fmt.Sprintf("Chain ID: %s, Type: %s, Family: %s, Container: %s, Nodes: %d, RPC: %s",
		info.ChainID, info.Type, info.Family, info.ContainerName, nodeCount, rpcURL), nil
}

// GetWebSocketEndpoint returns the WebSocket endpoint for a blockchain by chain selector
// Returns the first available WebSocket endpoint.
func (bh *BlockchainHelper) GetWebSocketEndpoint(chainSelector protocltypes.ChainSelector) (string, error) {
	info, err := bh.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return "", err
	}

	if len(info.Nodes) == 0 {
		return "", fmt.Errorf("no nodes found for chain %d", uint64(chainSelector))
	}

	if info.Nodes[0].ExternalWSUrl == "" {
		return "", fmt.Errorf("no WebSocket URL found for chain %d", uint64(chainSelector))
	}

	return info.Nodes[0].ExternalWSUrl, nil
}

// GetAllNodes returns all nodes for a blockchain by chain selector.
func (bh *BlockchainHelper) GetAllNodes(chainSelector protocltypes.ChainSelector) ([]*Node, error) {
	info, err := bh.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return nil, err
	}

	return info.Nodes, nil
}

// GetInternalRPCEndpoint returns the internal RPC endpoint for a blockchain by chain selector
// Useful for container-to-container communication.
func (bh *BlockchainHelper) GetInternalRPCEndpoint(chainSelector protocltypes.ChainSelector) (string, error) {
	info, err := bh.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return "", err
	}

	if len(info.Nodes) == 0 {
		return "", fmt.Errorf("no nodes found for chain %d", uint64(chainSelector))
	}

	if info.Nodes[0].InternalHTTPUrl == "" {
		return "", fmt.Errorf("no internal HTTP URL found for chain %d", uint64(chainSelector))
	}

	return info.Nodes[0].InternalHTTPUrl, nil
}
