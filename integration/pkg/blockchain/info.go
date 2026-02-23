package blockchain

import (
	"fmt"
	"strconv"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain/canton"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type NetworkSpecificData struct {
	CantonEndpoints *canton.Endpoints `json:"canton_endpoints"`
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

// GetBlockchainByChainSelector returns the blockchain info for a given chain selector.
func (bh *Helper) GetBlockchainByChainSelector(chainSelector protocol.ChainSelector) (*Info, error) {
	selector := fmt.Sprintf("%d", uint64(chainSelector))
	if info, exists := bh.infos[selector]; exists && info != nil {
		return info, nil
	}
	return nil, fmt.Errorf("selector %d not found", uint64(chainSelector))
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

func (bi *Info) String() string {
	nodeCount := len(bi.Nodes)
	var rpcURL string
	if nodeCount > 0 && bi.Nodes[0] != nil && bi.Nodes[0].ExternalHTTPUrl != "" {
		rpcURL = bi.Nodes[0].ExternalHTTPUrl
	} else {
		rpcURL = "N/A"
	}
	return fmt.Sprintf("Chain ID: %s, Type: %s, Family: %s, ChainName: %s, Nodes: %d, RPC: %s, NetworkSpecificData: %+v",
		bi.ChainID, bi.Type, bi.Family, bi.UniqueChainName, nodeCount, rpcURL, bi.NetworkSpecificData)
}

func (bi *Info) GetFirstNode() (Node, error) {
	if bi == nil {
		return Node{}, fmt.Errorf("blockchain info is nil")
	}
	for _, node := range bi.Nodes {
		if node != nil && (*node != Node{}) {
			return *node, nil
		}
	}

	return Node{}, fmt.Errorf("no nodes found for chain %s", bi.ChainID)
}

func (bh *Helper) GetNetworkSpecificData(chainSelector protocol.ChainSelector) (*NetworkSpecificData, error) {
	bi, err := bh.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return nil, err
	}
	if bi == nil {
		return nil, fmt.Errorf("blockchain info is nil for selector %d", uint64(chainSelector))
	}

	return bi.NetworkSpecificData, nil
}
