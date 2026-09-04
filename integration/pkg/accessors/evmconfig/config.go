// Package evmconfig is the operator-facing EVM configuration surface: the mounted config format,
// the loader that also accepts a Chainlink node's own TOML, the conversion between the two, and the
// projection of what a chain will effectively run.
//
// It registers no accessor factory and pulls in none of the chainlink-evm runtime, so config
// readers and generators — devenv, configdoc, `ccv migrate inspect-config` — can depend on it
// without the EVM driver's init() reaching a binary that runs no EVM chains. Importing
// github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm remains the deliberate
// opt-in that registers the EVM family with chainaccess.
package evmconfig

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
	// Zero enables finality-tag mode; a positive value uses confirmation-depth mode.
	FinalityDepth uint32 `toml:"finality_depth,omitempty"`
	// TXMBlockTime controls TXM v2's retry cadence. It is not the chain's actual block
	// time and is not used outside the transaction manager. Zero uses the standalone
	// default; non-zero values must be at least two seconds.
	TXMBlockTime time.Duration `toml:"txm_block_time,omitempty"`
	// SourceReaderHeaderFetchBatchSize caps how many eth_getBlockByNumber requests
	// are sent in a single JSON-RPC batch when the source reader fetches block
	// headers. Zero uses [DefaultSourceReaderHeaderFetchBatchSize], which is 25.
	SourceReaderHeaderFetchBatchSize int `toml:"source_reader_header_fetch_batch_size,omitempty"`
}

// DefaultSourceReaderHeaderFetchBatchSize is the batch size used when the
// operator config does not set SourceReaderHeaderFetchBatchSize.
const DefaultSourceReaderHeaderFetchBatchSize = 25

// NewConfigFromInfos builds operator config from the enumeration-oriented
// Infos[Info] produced by devenv, dropping metadata derived from the selector.
func NewConfigFromInfos(infos chainaccess.Infos[Info]) Config {
	chains := make(map[string]ChainConfig, len(infos))
	for selector, info := range infos {
		chains[selector] = ChainConfig{
			Nodes:                            nodesWithDefaultNames(info),
			FinalityDepth:                    info.FinalityDepth,
			TXMBlockTime:                     info.TXMBlockTime,
			SourceReaderHeaderFetchBatchSize: info.SourceReaderHeaderFetchBatchSize,
		}
	}
	return Config{Chains: chains}
}

// Node is the focused RPC endpoint subset exposed by standalone CCV. It deliberately does not
// embed chainlink-evm's Node type, whose additional fields are not operator settings for CCV.
// Each node carries a single endpoint pair, addressed from the process that loads this config.
// Environments that reach the same RPC through more than one address, such as devenv bridging a
// Docker network to the host, resolve that at config generation time rather than here.
type Node struct {
	// Name identifies the RPC provider or endpoint in logs and health reports.
	Name string `json:"name" toml:"name,omitempty"`
	// HTTPUrl is the JSON-RPC endpoint used for reads and transaction submission. It is required.
	HTTPUrl string `json:"http_url" toml:"http_url"`
	// WSUrl is the optional WebSocket endpoint used for head subscriptions. Nodes without one
	// fall back to HTTP head polling.
	WSUrl string `json:"ws_url" toml:"ws_url,omitempty"`
	// Order is the node's selection priority, 1 (highest) through 100 (lowest). When several nodes
	// are equally healthy the multi-node pool prefers the one with the lowest Order value, so an
	// operator can keep a primary RPC ahead of its backups. Zero is the default and leaves Order
	// unset: the conversion sends no Order to chainlink-evm, which then applies its own default
	// priority. A converted Chainlink node config carries each node's Order over unchanged.
	Order int32 `json:"order,omitempty" toml:"order,omitempty"`
}

func (n Node) String() string {
	return fmt.Sprintf("Name: %s, HTTP: %s, WS: %s", n.Name, n.HTTPUrl, n.WSUrl)
}

func (n Node) Empty() bool {
	return n.HTTPUrl == "" && n.WSUrl == ""
}

// Info represents blockchain connection information.
type Info struct {
	ChainID                          string        `json:"chain_id"                              toml:"chain_id"`
	Type                             string        `json:"type"                                  toml:"type"`
	Family                           string        `json:"family"                                toml:"family"`
	UniqueChainName                  string        `json:"unique_chain_name"                     toml:"unique_chain_name"`
	Nodes                            []Node        `json:"nodes"                                 toml:"nodes"`
	FinalityDepth                    uint32        `json:"finality_depth"                        toml:"finality_depth"`
	TXMBlockTime                     time.Duration `json:"txm_block_time"                        toml:"txm_block_time"`
	SourceReaderHeaderFetchBatchSize int           `json:"source_reader_header_fetch_batch_size" toml:"source_reader_header_fetch_batch_size"`
}

func (bi Info) Empty() bool {
	return bi.ChainID == "" && bi.Type == "" && bi.Family == "" && bi.UniqueChainName == "" &&
		len(bi.Nodes) == 0 && bi.FinalityDepth == 0 && bi.TXMBlockTime == 0 &&
		bi.SourceReaderHeaderFetchBatchSize == 0
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
