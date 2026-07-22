package evm

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

const (
	EVMConfigPathEnv     = "EVM_CONFIG_PATH"
	DefaultEVMConfigPath = "/etc/evm/config.toml"
)

// Config is the EVM operator-local config mounted into standalone containers. It carries only
// NOP-owned settings — RPC endpoints and chain-type tuning — keyed by chain selector. It is
// intentionally CCV-owned rather than an alias of chainlink-evm's much larger configuration;
// chainlink_config.go contains the single explicit adapter to that upstream model. Chain ID and
// family are derived from the selector, not stored here. This mirrors the Solana and Canton
// local-config pattern, keeping connection details out of the JD job spec's blockchain_infos.
type Config struct {
	// Chains maps EVM chain selector (decimal string) to its operator-local settings.
	Chains map[string]ChainConfig `toml:"chains"`
}

// ChainConfig is the operator-owned local configuration for a single EVM chain.
type ChainConfig struct {
	// Nodes are the RPC endpoints used to reach this chain.
	Nodes []Node `toml:"nodes"`
	// ChainType selects family-specific EVM client behavior (for example optimismBedrock or
	// arbitrum). Empty means generic EVM. It is not derivable from the selector, so operators
	// supply it here.
	ChainType string `toml:"chain_type,omitempty"`
	// UniqueChainName is an optional human-readable label used in logs and node names.
	UniqueChainName string `toml:"unique_chain_name,omitempty"`
}

// NewConfigFromInfos builds a Config from the enumeration-oriented Infos[Info] produced by devenv,
// dropping the fields (chain ID, family) that the accessor derives from the selector at load time.
func NewConfigFromInfos(infos chainaccess.Infos[Info]) Config {
	chains := make(map[string]ChainConfig, len(infos))
	for selector, info := range infos {
		chains[selector] = ChainConfig{
			Nodes:           info.Nodes,
			ChainType:       info.Type,
			UniqueChainName: info.UniqueChainName,
		}
	}
	return Config{Chains: chains}
}

// Node is the focused RPC endpoint subset exposed by standalone CCV. It deliberately does not
// embed chainlink-evm's Node type, whose additional fields are not operator settings for CCV.
type Node struct {
	ExternalHTTPUrl string `json:"external_http_url" toml:"external_http_url"`
	InternalHTTPUrl string `json:"internal_http_url" toml:"internal_http_url"`
	ExternalWSUrl   string `json:"external_ws_url"   toml:"external_ws_url"`
	InternalWSUrl   string `json:"internal_ws_url"   toml:"internal_ws_url"`
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
	ChainID         string `json:"chain_id"          toml:"chain_id"`
	Type            string `json:"type"              toml:"type"`
	Family          string `json:"family"            toml:"family"`
	UniqueChainName string `json:"unique_chain_name" toml:"unique_chain_name"`
	Nodes           []Node `json:"nodes"             toml:"nodes"`
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
