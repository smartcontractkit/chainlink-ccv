package evm

import (
	"fmt"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

const (
	EVMConfigPathEnv     = "EVM_CONFIG_PATH"
	DefaultEVMConfigPath = "/etc/evm/config.toml"
)

// Config is the EVM operator-local config mounted into standalone containers. It carries only
// NOP-owned settings keyed by chain selector. It is intentionally CCV-owned rather than an alias
// of chainlink-evm's much larger configuration; chainlink_config.go contains the single explicit
// adapter to that upstream model. Chain ID, family, and chain type are derived from the selector,
// not stored here. This mirrors the Solana and Canton local-config pattern, keeping connection
// details out of the JD job spec's blockchain_infos.
type Config struct {
	// Chains maps EVM chain selector (decimal string) to its operator-local settings.
	Chains map[string]ChainConfig `toml:"chains"`
}

// ChainConfig is the operator-owned local configuration for a single EVM chain.
type ChainConfig struct {
	// Nodes are the RPC endpoints used to reach this chain.
	Nodes []Node `toml:"nodes"`
	// FinalityDepth is the number of blocks required before a head is considered final.
	// Zero uses CCV's default confirmation depth.
	FinalityDepth uint32 `toml:"finality_depth,omitempty"`
	// BlockTime controls TXM v2's retry cadence. Zero uses the standalone default;
	// non-zero values must be at least two seconds.
	BlockTime time.Duration `toml:"block_time,omitempty"`
}

// NewConfigFromInfos builds operator config from the enumeration-oriented
// Infos[Info] produced by devenv, dropping metadata derived from the selector.
func NewConfigFromInfos(infos chainaccess.Infos[Info]) Config {
	chains := make(map[string]ChainConfig, len(infos))
	for selector, info := range infos {
		chains[selector] = ChainConfig{
			Nodes:         nodesWithDefaultNames(info),
			FinalityDepth: info.FinalityDepth,
			BlockTime:     info.BlockTime,
		}
	}
	return Config{Chains: chains}
}

// Node is the focused RPC endpoint subset exposed by standalone CCV. It deliberately does not
// embed chainlink-evm's Node type, whose additional fields are not operator settings for CCV.
type Node struct {
	// Name identifies the RPC provider or endpoint in logs and health reports.
	Name            string `json:"name"              toml:"name,omitempty"`
	ExternalHTTPUrl string `json:"external_http_url" toml:"external_http_url"`
	InternalHTTPUrl string `json:"internal_http_url" toml:"internal_http_url"`
	ExternalWSUrl   string `json:"external_ws_url"   toml:"external_ws_url"`
	InternalWSUrl   string `json:"internal_ws_url"   toml:"internal_ws_url"`
}

func (n Node) String() string {
	return fmt.Sprintf("Name: %s, ExternalHTTP: %s, InternalHTTP: %s, ExternalWS: %s, InternalWS: %s",
		n.Name, n.ExternalHTTPUrl, n.InternalHTTPUrl, n.ExternalWSUrl, n.InternalWSUrl)
}

func (n Node) Empty() bool {
	return n.ExternalHTTPUrl == "" && n.InternalHTTPUrl == "" && n.ExternalWSUrl == "" && n.InternalWSUrl == ""
}

// Info represents blockchain connection information.
type Info struct {
	ChainID         string        `json:"chain_id"          toml:"chain_id"`
	Type            string        `json:"type"              toml:"type"`
	Family          string        `json:"family"            toml:"family"`
	UniqueChainName string        `json:"unique_chain_name" toml:"unique_chain_name"`
	Nodes           []Node        `json:"nodes"             toml:"nodes"`
	FinalityDepth   uint32        `json:"finality_depth"    toml:"finality_depth"`
	BlockTime       time.Duration `json:"block_time"        toml:"block_time"`
}

func (bi Info) Empty() bool {
	return bi.ChainID == "" && bi.Type == "" && bi.Family == "" && bi.UniqueChainName == "" &&
		len(bi.Nodes) == 0 && bi.FinalityDepth == 0 && bi.BlockTime == 0
}

func nodesWithDefaultNames(info Info) []Node {
	nodes := append([]Node(nil), info.Nodes...)
	for i := range nodes {
		if strings.TrimSpace(nodes[i].Name) == "" {
			nodes[i].Name = defaultNodeName(info, i)
		}
	}
	return nodes
}

func defaultNodeName(info Info, index int) string {
	// UniqueChainName is legacy enumeration metadata used only to make generated
	// devenv node names readable. Mounted operator config uses Node.Name.
	base := strings.TrimSpace(info.UniqueChainName)
	if base == "" {
		base = "evm-" + info.ChainID
	}
	if len(info.Nodes) == 1 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, index+1)
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
