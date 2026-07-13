package evm

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

const (
	EVMConfigPathEnv     = "EVM_CONFIG_PATH"
	DefaultEVMConfigPath = "/etc/evm/config.toml"
)

// Config holds chain-specific configuration for the EVM CCIP integration.
type Config struct {
	// BlockchainInfos maps EVM chain selectors to their connection information.
	BlockchainInfos chainaccess.Infos[Info] `toml:"blockchain_infos"`
}

// Node represents a blockchain node with connection information.
type Node struct {
	ExternalHTTPUrl string `json:"external_http_url" toml:"external_http_url"`
	InternalHTTPUrl string `json:"internal_http_url" toml:"internal_http_url"`
	ExternalWSUrl   string `json:"external_ws_url" toml:"external_ws_url"`
	InternalWSUrl   string `json:"internal_ws_url" toml:"internal_ws_url"`
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
	ChainID         string `json:"chain_id" toml:"chain_id"`
	Type            string `json:"type" toml:"type"`
	Family          string `json:"family" toml:"family"`
	UniqueChainName string `json:"unique_chain_name" toml:"unique_chain_name"`
	Nodes           []Node `json:"nodes" toml:"nodes"`
}

func (bi Info) Empty() bool {
	return bi.ChainID == "" && bi.Type == "" && bi.Family == "" && bi.UniqueChainName == "" && len(bi.Nodes) == 0
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
