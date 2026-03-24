package blockchain

import (
	"fmt"
	"strconv"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// Node represents a blockchain node with connection information.
// TODO: make this chain family agnostic.
type Node struct {
	ExternalHTTPUrl string `json:"external_http_url"`
	InternalHTTPUrl string `json:"internal_http_url"`
	ExternalWSUrl   string `json:"external_ws_url"`
	InternalWSUrl   string `json:"internal_ws_url"`
}

func (n Node) String() string {
	return fmt.Sprintf("ExternalHTTP: %s, InternalHTTP: %s, ExternalWS: %s, InternalWS: %s",
		n.ExternalHTTPUrl, n.InternalHTTPUrl, n.ExternalWSUrl, n.InternalWSUrl)
}

func (n Node) Empty() bool {
	return n.ExternalHTTPUrl == "" && n.InternalHTTPUrl == "" && n.ExternalWSUrl == "" && n.InternalWSUrl == ""
}

// Info represents blockchain connection information.
type Info struct {
	ChainID         string `json:"chain_id"`
	Type            string `json:"type"`
	Family          string `json:"family"`
	UniqueChainName string `json:"unique_chain_name"`
	Nodes           []Node `json:"nodes"`
}

func (bi Info) Empty() bool {
	return bi.ChainID == "" && bi.Type == "" && bi.Family == "" && bi.UniqueChainName == "" && len(bi.Nodes) == 0
}

type Infos map[string]Info

// GetBlockchainByChainSelector returns the blockchain info for a given chain selector.
func (bh Infos) GetBlockchainByChainSelector(chainSelector protocol.ChainSelector) (Info, error) {
	selector := fmt.Sprintf("%d", uint64(chainSelector))
	if info, exists := bh[selector]; exists && !info.Empty() {
		return info, nil
	}
	return Info{}, fmt.Errorf("selector %d not found", uint64(chainSelector))
}

// GetAllChainSelectors returns all available chain selectors.
func (bh Infos) GetAllChainSelectors() []protocol.ChainSelector {
	selectors := make([]protocol.ChainSelector, 0)
	for sel := range bh {
		selector, err := strconv.ParseUint(sel, 10, 64)
		if err != nil {
			continue
		}
		selectors = append(selectors, protocol.ChainSelector(selector))
	}
	return selectors
}

func (bi Info) String() string {
	nodeCount := len(bi.Nodes)
	firstNode := "N/A"
	if n, err := bi.GetFirstNode(); err == nil {
		firstNode = n.String()
	}
	return fmt.Sprintf("Chain ID: %s, Type: %s, Family: %s, ChainName: %s, Nodes: %d, First Node: [%s]",
		bi.ChainID, bi.Type, bi.Family, bi.UniqueChainName, nodeCount, firstNode)
}

func (bi Info) GetFirstNode() (Node, error) {
	for _, node := range bi.Nodes {
		if !node.Empty() {
			return node, nil
		}
	}

	return Node{}, fmt.Errorf("no nodes found for chain %s", bi.ChainID)
}
