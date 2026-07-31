// Conversion of a Chainlink node's EVM configuration into the standalone operator config. A node
// operator moving off CL mode mounts the config file their node already runs with; loadConfig
// detects it and converts it here, so the endpoints and finality behavior carry over without anyone
// hand-writing a second file.
package evm

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	chainsel "github.com/smartcontractkit/chain-selectors"
	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
)

// Conversion is the converted config together with everything the conversion dropped or decided.
// Warnings are not failures: they are the settings a Chainlink node accepts that standalone CCV has
// no equivalent for. CreateEVMAccessorFactory logs them at warn on startup, so an operator who
// mounted their node's file sees what changed rather than finding out from behavior.
//
// Warnings are ordered as the operator wrote the config: by chain, then by node within the chain,
// then by setting. A converted config with no warnings is normal and does not mean no conversion
// happened, which is why loadConfig reports the conversion itself rather than the warning count.
type Conversion struct {
	Config   Config
	Warnings []string
}

// nodeConfigFile is the sliver of a Chainlink node's TOML that this conversion reads. Every other
// section — Log, WebServer, P2P, Database — is ignored, so a whole node config can be passed in
// as-is.
type nodeConfigFile struct {
	EVM evmtoml.EVMConfigs `toml:"EVM"`
}

// convertChainlinkNodeConfig reads a Chainlink node TOML configuration and produces the standalone EVM operator
// config. Chain IDs are resolved to chain selectors, so a chain the node runs that CCV has no
// selector for is an error rather than a silently missing chain.
func convertChainlinkNodeConfig(nodeTOML []byte) (Conversion, error) {
	var parsed nodeConfigFile
	if err := toml.Unmarshal(nodeTOML, &parsed); err != nil {
		return Conversion{}, fmt.Errorf("failed to parse Chainlink node config: %w", err)
	}
	if len(parsed.EVM) == 0 {
		return Conversion{}, fmt.Errorf("config has no [[EVM]] sections: pass the node's TOML config, " +
			"the one holding [[EVM]] and [[EVM.Nodes]]")
	}

	merged, err := mergeByChainID(parsed.EVM)
	if err != nil {
		return Conversion{}, err
	}

	var warnings []string
	chains := make(map[string]ChainConfig, len(merged))
	for _, cfg := range merged {
		chainID := cfg.ChainID.String()
		if !cfg.IsEnabled() {
			warnings = append(warnings, fmt.Sprintf("chain %s: skipped, the node has it disabled", chainID))
			continue
		}

		details, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
		if err != nil {
			return Conversion{}, fmt.Errorf("chain %s has no known chain selector: %w", chainID, err)
		}

		nodes, nodeWarnings, err := convertNodes(chainID, cfg.Nodes)
		if err != nil {
			return Conversion{}, err
		}
		warnings = append(warnings, nodeWarnings...)

		finalityDepth, err := convertFinality(cfg)
		if err != nil {
			return Conversion{}, err
		}

		chains[strconv.FormatUint(details.ChainSelector, 10)] = ChainConfig{
			Nodes:         nodes,
			FinalityDepth: finalityDepth,
			TXMBlockTime:  txmBlockTimeOverride(cfg),
		}
	}

	if len(chains) == 0 {
		return Conversion{}, fmt.Errorf("config declares no enabled EVM chains")
	}
	return Conversion{Config: Config{Chains: chains}, Warnings: warnings}, nil
}

// mergeByChainID collapses repeated [[EVM]] blocks for the same chain, later blocks overriding
// earlier ones, which is how a Chainlink node itself reads them. Order of first appearance is
// preserved so warnings come out in the order the operator wrote their config.
func mergeByChainID(configs evmtoml.EVMConfigs) ([]*evmtoml.EVMConfig, error) {
	var order []string
	byID := make(map[string]*evmtoml.EVMConfig, len(configs))
	for i, cfg := range configs {
		if cfg == nil {
			continue
		}
		if cfg.ChainID == nil || cfg.ChainID.String() == "" {
			return nil, fmt.Errorf("[[EVM]] entry %d has no ChainID", i)
		}
		id := cfg.ChainID.String()
		if existing, ok := byID[id]; ok {
			existing.SetFrom(cfg)
			continue
		}
		byID[id] = cfg
		order = append(order, id)
	}

	out := make([]*evmtoml.EVMConfig, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, nil
}

// convertNodes maps the node's RPC endpoints onto CCV's narrower node type. CCV models one HTTP
// endpoint and an optional WebSocket endpoint per node and nothing else, so anything a Chainlink
// node can express beyond that is dropped with a warning rather than approximated.
func convertNodes(chainID string, nodes evmtoml.EVMNodes) ([]Node, []string, error) {
	if len(nodes) == 0 {
		return nil, nil, fmt.Errorf("chain %s has no [[EVM.Nodes]] entries", chainID)
	}

	var warnings []string
	converted := make([]Node, 0, len(nodes))
	for i, node := range nodes {
		if node == nil {
			continue
		}
		name := ""
		if node.Name != nil {
			name = *node.Name
		}
		label := name
		if label == "" {
			label = fmt.Sprintf("index %d", i)
		}

		// A send-only node is broadcast-only on a Chainlink node. CCV has no such concept, and
		// carrying it over as an ordinary node would make it eligible for reads and head tracking —
		// which is exactly what the operator marked it unfit for. Dropping it is the safe reading.
		if node.SendOnly != nil && *node.SendOnly {
			warnings = append(warnings, fmt.Sprintf(
				"chain %s node %s: dropped, SendOnly nodes have no standalone equivalent", chainID, label))
			continue
		}
		if node.HTTPURL == nil {
			return nil, nil, fmt.Errorf(
				"chain %s node %s has no HTTPURL; standalone CCV requires an HTTP endpoint for every node",
				chainID, label)
		}

		// A slice rather than a map so the warnings come out in a fixed order, which keeps them
		// grouped per node in the order the operator wrote the nodes.
		for _, dropped := range []struct {
			setting string
			isSet   bool
		}{
			{"HTTPURLExtraWrite", node.HTTPURLExtraWrite != nil},
			{"Order", node.Order != nil},
			{"IsLoadBalancedRPC", node.IsLoadBalancedRPC != nil},
		} {
			if dropped.isSet {
				warnings = append(warnings, fmt.Sprintf(
					"chain %s node %s: dropped %s, standalone CCV does not expose it", chainID, label, dropped.setting))
			}
		}

		converted = append(converted, Node{
			Name:    name,
			HTTPUrl: urlString(node.HTTPURL),
			WSUrl:   urlString(node.WSURL),
		})
	}

	if len(converted) == 0 {
		return nil, nil, fmt.Errorf("chain %s has no usable [[EVM.Nodes]] entries after conversion", chainID)
	}
	return converted, warnings, nil
}

// convertFinality maps the node's finality settings onto CCV's single finality_depth field, where
// zero selects finality-tag mode and a positive value selects confirmation-depth mode.
//
// The node's own defaults are applied first. A chain whose default is confirmation-depth mode
// behaves that way even when the operator's file says nothing about finality, so reading only the
// explicit settings would quietly move that chain onto finality tags.
func convertFinality(cfg *evmtoml.EVMConfig) (uint32, error) {
	effective := evmtoml.Defaults(cfg.ChainID, &cfg.Chain)
	if effective.FinalityTagEnabled != nil && *effective.FinalityTagEnabled {
		return 0, nil
	}
	if effective.FinalityDepth == nil || *effective.FinalityDepth == 0 {
		return 0, fmt.Errorf(
			"chain %s uses confirmation-depth finality but has no FinalityDepth; set FinalityDepth or FinalityTagEnabled",
			cfg.ChainID.String())
	}
	return *effective.FinalityDepth, nil
}

// txmBlockTimeOverride returns the operator's explicit TXM v2 block time, or zero to take CCV's own
// default. Only an explicit value carries over: the node's default for this setting applies to a
// transaction manager the node may not even run, so inheriting it would be inventing a tuning
// decision the operator never made.
func txmBlockTimeOverride(cfg *evmtoml.EVMConfig) time.Duration {
	blockTime := cfg.Transactions.TransactionManagerV2.BlockTime
	if blockTime == nil {
		return 0
	}
	return blockTime.Duration()
}

func urlString(u *commonconfig.URL) string {
	if u == nil {
		return ""
	}
	return strings.TrimSpace((*url.URL)(u).String())
}
