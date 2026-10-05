// Conversion of a Chainlink node's EVM configuration into the standalone operator config. A node
// operator moving off CL mode mounts the config file their node already runs with; LoadConfigFile
// detects it and converts it here, so the endpoints and finality behavior carry over without anyone
// hand-writing a second file.
package evmconfig

import (
	"fmt"
	"net/url"
	"sort"
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
// with the dropped settings within each sorted. A converted config with no warnings is normal and
// does not mean no conversion happened, which is why LoadConfigFile reports the conversion itself
// rather than the warning count.
type Conversion struct {
	Config   Config
	Warnings []string
	// WarningsByChainID holds the same warnings grouped by the chain that produced them, so a
	// per-chain view — `ccv migrate inspect-config --chain-selector` — narrows them without parsing
	// the message text. Keyed by chain ID rather than selector because a warning is written before
	// the chain's selector is resolved, and because a chain the node has disabled never gets one.
	WarningsByChainID map[string][]string
	// IgnoredSections names the node config's top-level sections outside [[EVM]] — Log, WebServer,
	// P2P, Database and the like — which the conversion does not read at all. It is file-level
	// rather than per-chain, so it sits outside the two warning views, and sorted rather than in
	// file order.
	IgnoredSections []string
	// FailedChains holds the enabled chains that could not be converted at all — an unknown chain
	// ID, no usable RPC endpoint, an unservable finality mode — each with the reason. Their chains
	// are absent from Config, and each also appears as a skip line in the warning views. Conversion
	// reports them rather than failing so one leftover or mistyped chain cannot take down the
	// config for every other chain the node runs; whether a skip is acceptable is a policy decision
	// for the caller (the bootstrapper fails the boot when a skipped chain is one the operator
	// declared in [[chains]], via the chain family's registered coverage checker — the EVM driver
	// at integration/pkg/accessors/evm registers one against this conversion).
	FailedChains []ChainFailure
	// DisabledChains holds the chain IDs the node config disables explicitly, in file order. An
	// explicit disable is a choice, not a gap: it passes the declared-chain coverage check (the
	// declaration still registers the key), while FailedChains entries do not.
	DisabledChains []string
}

// ChainFailure is one chain the conversion had to skip whole, with the reason in operator-facing
// wording. ChainID is the decimal chain ID as written in the node config.
type ChainFailure struct {
	ChainID string `json:"chain_id"`
	Reason  string `json:"reason"`
}

// nodeConfigFile is the sliver of a Chainlink node's TOML that this conversion reads. Every other
// section — Log, WebServer, P2P, Database — is ignored, so a whole node config can be passed in
// as-is.
type nodeConfigFile struct {
	EVM evmtoml.EVMConfigs `toml:"EVM"`
}

// convertChainlinkNodeConfig reads a Chainlink node TOML configuration and produces the standalone EVM operator
// config. Chain IDs are resolved to chain selectors. A chain that cannot be converted — an unknown
// chain ID, no usable RPC endpoint, an unservable finality mode — is skipped and reported in
// FailedChains rather than failing the whole file, so one leftover or mistyped chain cannot take
// down every other chain the node runs. The only hard errors are a malformed file and a file with
// no usable chain at all.
func convertChainlinkNodeConfig(nodeTOML []byte) (Conversion, error) {
	var parsed nodeConfigFile
	if err := toml.Unmarshal(nodeTOML, &parsed); err != nil {
		return Conversion{}, fmt.Errorf("failed to parse Chainlink node config: %w", err)
	}
	if len(parsed.EVM) == 0 {
		return Conversion{}, fmt.Errorf("config has no [[EVM]] sections: pass the node's TOML config, " +
			"the one holding [[EVM]] and [[EVM.Nodes]]")
	}

	// The raw decode drives set-detection: only the file's own keys can say what the operator
	// actually wrote, including settings the pinned chainlink-evm types have no field for — a
	// newer node's options, a typo of a real one — and scalars a typed walk cannot tell from
	// unset. The typed decode above already succeeded, so this cannot fail in practice; if it
	// ever did, warnings degrade rather than taking a loadable config down.
	raw := decodeRawNodeConfig(nodeTOML)
	ignoredSections := ignoredTopLevelSections(raw)
	rawChains := rawChainsByChainID(raw)

	merged, err := mergeByChainID(parsed.EVM)
	if err != nil {
		return Conversion{}, err
	}

	var warnings []string
	warningsByChainID := make(map[string][]string, len(merged))
	var failedChains []ChainFailure
	var disabledChains []string
	chains := make(map[string]ChainConfig, len(merged))
	// Every warning is attributable to the chain being converted, so each iteration collects its own
	// and the flat list is built from those. The two views cannot drift.
	for _, cfg := range merged {
		chainID := cfg.ChainID.String()

		// A chain that cannot run standalone is skipped, not fatal: the reason is recorded in
		// FailedChains and warned about, and the remaining chains still convert. Whether the skip
		// is acceptable is the caller's policy decision.
		fail := func(reason string) {
			failedChains = append(failedChains, ChainFailure{ChainID: chainID, Reason: reason})
			skipped := fmt.Sprintf("chain %s: skipped, %s", chainID, reason)
			warnings = append(warnings, skipped)
			warningsByChainID[chainID] = []string{skipped}
		}

		if !cfg.IsEnabled() {
			disabledChains = append(disabledChains, chainID)
			skipped := fmt.Sprintf("chain %s: skipped, the node has it disabled", chainID)
			warnings = append(warnings, skipped)
			warningsByChainID[chainID] = []string{skipped}
			continue
		}

		details, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
		if err != nil {
			fail(fmt.Sprintf("its chain ID has no known chain selector: %v", err))
			continue
		}

		rawChain := rawChains[chainID]
		var rawNodes []map[string]any
		if rawChain != nil {
			rawNodes = rawChain.nodes
		}
		nodes, nodeWarnings, err := convertNodes(chainID, cfg.Nodes, rawNodes)
		if err != nil {
			fail(err.Error())
			continue
		}

		finalityDepth, err := convertFinality(cfg)
		if err != nil {
			fail(err.Error())
			continue
		}

		chains[strconv.FormatUint(details.ChainSelector, 10)] = ChainConfig{
			Nodes:         nodes,
			FinalityDepth: finalityDepth,
			TXMBlockTime:  txmBlockTimeOverride(cfg),
		}

		// The chain-level dropped-settings warning emits ahead of the node warnings to keep the
		// chain's warnings in the operator's file order: [[EVM]] settings come before its
		// [[EVM.Nodes]] entries. Only a chain that converted warns about drops — for a skipped
		// chain everything was dropped, which the skip line already says.
		var chainWarnings []string
		if rawChain != nil {
			if dropped := droppedChainSettingPaths(rawChain.blocks); len(dropped) > 0 {
				chainWarnings = append(chainWarnings, fmt.Sprintf(
					"chain %s: dropped set chain-level settings with no standalone equivalent: %s",
					chainID, strings.Join(dropped, ", ")))
			}
		}
		chainWarnings = append(chainWarnings, nodeWarnings...)
		if len(chainWarnings) > 0 {
			warnings = append(warnings, chainWarnings...)
			warningsByChainID[chainID] = chainWarnings
		}
	}

	if len(chains) == 0 {
		// Every enabled chain failing means the wrong file was mounted, not that there is nothing
		// to serve: name every reason so one boot log carries all of them.
		if len(failedChains) > 0 {
			reasons := make([]string, 0, len(failedChains))
			for _, f := range failedChains {
				reasons = append(reasons, fmt.Sprintf("chain %s %s", f.ChainID, f.Reason))
			}
			return Conversion{}, fmt.Errorf("config has no usable EVM chains: every enabled chain failed to convert: %s",
				strings.Join(reasons, "; "))
		}
		return Conversion{}, fmt.Errorf("config declares no enabled EVM chains")
	}
	return Conversion{
		Config:            Config{Chains: chains},
		Warnings:          warnings,
		WarningsByChainID: warningsByChainID,
		IgnoredSections:   ignoredSections,
		FailedChains:      failedChains,
		DisabledChains:    disabledChains,
	}, nil
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

// carriedOverChainSettings lists, by lower-cased dotted path as written in the operator's file,
// the chain-level keys the conversion reads: ChainID, Enabled and Nodes are read by the conversion
// itself, the finality pair by convertFinality, and the block time by txmBlockTimeOverride. Every
// other key present in the file is dropped, so it must surface in a warning rather than disappear
// quietly.
var carriedOverChainSettings = map[string]struct{}{
	"chainid":            {},
	"enabled":            {},
	"nodes":              {},
	"finalitydepth":      {},
	"finalitytagenabled": {},
	"transactions.transactionmanagerv2.blocktime": {},
}

// carriedOverNodeSettings is the node-level equivalent: the keys convertNodes reads. SendOnly is
// read too — a send-only node is dropped wholesale, with its own warning.
var carriedOverNodeSettings = map[string]struct{}{
	"name":     {},
	"httpurl":  {},
	"wsurl":    {},
	"order":    {},
	"sendonly": {},
}

// decodeRawNodeConfig decodes the mounted file without the chainlink-evm types, for set-detection
// only. A nil result degrades warnings, never the conversion.
func decodeRawNodeConfig(nodeTOML []byte) map[string]any {
	var raw map[string]any
	if err := toml.Unmarshal(nodeTOML, &raw); err != nil {
		return nil
	}
	return raw
}

// ignoredTopLevelSections names the node config's top-level sections outside EVM, sorted for a
// stable report. The conversion reads [[EVM]] and [[EVM.Nodes]] only; naming the rest here is
// what keeps "every other section is ignored" from being a silent drop.
func ignoredTopLevelSections(raw map[string]any) []string {
	var sections []string
	for key := range raw {
		if key == "EVM" {
			continue
		}
		sections = append(sections, key)
	}
	sort.Strings(sections)
	return sections
}

// rawChainConfig is one chain's raw TOML, grouped across repeated [[EVM]] blocks: every block for
// the set-detection union, plus the node tables of the last block that declares them — the node
// set mergeByChainID's override semantics keep.
type rawChainConfig struct {
	blocks []map[string]any
	nodes  []map[string]any
}

// rawTables normalizes a decoded TOML array of tables. go-toml yields []any of map[string]any
// for [[Section]] and a bare map[string]any when the operator wrote [Section] instead, so both
// spellings are accepted; anything else yields no tables rather than an error, because these
// warnings degrade rather than failing a config that already decoded.
func rawTables(value any) []map[string]any {
	switch typed := value.(type) {
	case []map[string]any:
		return typed
	case map[string]any:
		return []map[string]any{typed}
	case []any:
		tables := make([]map[string]any, 0, len(typed))
		for _, entry := range typed {
			if table, ok := entry.(map[string]any); ok {
				tables = append(tables, table)
			}
		}
		return tables
	default:
		return nil
	}
}

// rawChainsByChainID groups the raw [[EVM]] blocks by chain ID so each merged chain's
// set-detection reads exactly what the operator wrote for it. A block whose chain ID cannot be
// read is skipped: mergeByChainID has already rejected a missing one, and a warning lost here
// changes no behavior.
func rawChainsByChainID(raw map[string]any) map[string]*rawChainConfig {
	// go-toml decodes an array of tables into []any of map[string]any, never []map[string]any,
	// so the element type has to be asserted per entry. Asserting the slice type directly always
	// fails and silently disables set-detection.
	blocks := rawTables(raw["EVM"])
	if len(blocks) == 0 {
		return nil
	}
	chains := make(map[string]*rawChainConfig, len(blocks))
	for _, block := range blocks {
		chainID := rawChainID(block)
		if chainID == "" {
			continue
		}
		chain := chains[chainID]
		if chain == nil {
			chain = &rawChainConfig{}
			chains[chainID] = chain
		}
		chain.blocks = append(chain.blocks, block)
		if nodes := rawTables(block["Nodes"]); len(nodes) > 0 {
			chain.nodes = nodes
		}
	}
	return chains
}

func rawChainID(block map[string]any) string {
	switch chainID := block["ChainID"].(type) {
	case string:
		return chainID
	case int64:
		return strconv.FormatInt(chainID, 10)
	default:
		return ""
	}
}

// flattenSettingPaths walks a raw TOML table and appends the dotted path of every leaf it holds:
// a nested table recurses, anything else — a scalar, an array, an array of tables — is one leaf.
// joinSettingPath renders a setting's dotted path, so a nested key reports as
// "GasEstimator.Mode" rather than a bare "Mode" an operator cannot locate in their file.
func joinSettingPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// Reading the file rather than the decoded struct is what makes "set" exact: there is no
// set-vs-unset ambiguity to work around, and a key the typed config has no field for still shows.
func flattenSettingPaths(table map[string]any, prefix string, paths *[]string) {
	for key, value := range table {
		path := joinSettingPath(prefix, key)
		if nested, ok := value.(map[string]any); ok {
			flattenSettingPaths(nested, path, paths)
			continue
		}
		*paths = append(*paths, path)
	}
}

// droppedChainSettingPaths implements "warn on any set-but-dropped chain-level setting": the
// sorted union of the set keys across the chain's blocks that the conversion does not carry over.
// A later block overrides an earlier one but never un-sets a key, matching SetFrom, so the union
// is the operator's set view.
func droppedChainSettingPaths(blocks []map[string]any) []string {
	set := make(map[string]struct{})
	for _, block := range blocks {
		var paths []string
		flattenSettingPaths(block, "", &paths)
		for _, path := range paths {
			if _, carried := carriedOverChainSettings[strings.ToLower(path)]; carried {
				continue
			}
			set[path] = struct{}{}
		}
	}
	dropped := make([]string, 0, len(set))
	for path := range set {
		dropped = append(dropped, path)
	}
	sort.Strings(dropped)
	return dropped
}

// droppedNodeSettingPaths returns the sorted set-but-dropped keys of one raw node table.
func droppedNodeSettingPaths(node map[string]any) []string {
	var paths []string
	flattenSettingPaths(node, "", &paths)
	var dropped []string
	for _, path := range paths {
		if _, carried := carriedOverNodeSettings[strings.ToLower(path)]; carried {
			continue
		}
		dropped = append(dropped, path)
	}
	sort.Strings(dropped)
	return dropped
}

// convertNodes maps the node's RPC endpoints onto CCV's narrower node type. CCV models one HTTP
// endpoint, an optional WebSocket endpoint, and the node's selection priority (Order) per node and
// nothing else, so anything a Chainlink node can express beyond that is dropped with a warning
// rather than approximated. The dropped settings are named from the operator's file (rawNodes,
// paired with the decoded nodes by position — they are the same entries), so a node field this
// repo's chainlink-evm version predates is named too; a missing or short raw set degrades the
// warnings, never the conversion.
//
// Errors come back as bare reasons without the chain ID: the caller prefixes them with the chain
// when it records the chain as skipped.
func convertNodes(chainID string, nodes evmtoml.EVMNodes, rawNodes []map[string]any) ([]Node, []string, error) {
	if len(nodes) == 0 {
		return nil, nil, fmt.Errorf("has no [[EVM.Nodes]] entries")
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
			// The whole node goes, so its other settings go with it. They are named in this one
			// warning rather than as separate per-setting lines: a node that is not carried has
			// no setting that was individually dropped, and listing them as such reads as though
			// the node survived without them.
			dropped := ""
			if i < len(rawNodes) {
				if paths := droppedNodeSettingPaths(rawNodes[i]); len(paths) > 0 {
					dropped = fmt.Sprintf(" (%s dropped with it)", strings.Join(paths, ", "))
				}
			}
			warnings = append(warnings, fmt.Sprintf(
				"chain %s node %s: dropped, SendOnly nodes have no standalone equivalent%s", chainID, label, dropped))
			continue
		}
		if node.HTTPURL == nil {
			return nil, nil, fmt.Errorf(
				"node %s has no HTTPURL; standalone CCV requires an HTTP endpoint for every node",
				label)
		}

		if i < len(rawNodes) {
			for _, setting := range droppedNodeSettingPaths(rawNodes[i]) {
				warnings = append(warnings, fmt.Sprintf(
					"chain %s node %s: dropped %s, standalone CCV does not expose it", chainID, label, setting))
			}
		}

		// Order carries over so a converted node keeps the RPC prioritization the operator set on
		// their Chainlink node. An unset Order stays zero, which standalone CCV leaves at the pool's
		// lowest priority, matching how chainlink-evm treats a node with no Order.
		var order int32
		if node.Order != nil {
			order = *node.Order
		}
		converted = append(converted, Node{
			Name:    name,
			HTTPUrl: urlString(node.HTTPURL),
			WSUrl:   urlString(node.WSURL),
			Order:   order,
		})
	}

	if len(converted) == 0 {
		return nil, nil, fmt.Errorf("has no usable [[EVM.Nodes]] entries after conversion")
	}
	return converted, warnings, nil
}

// convertFinality maps the node's finality settings onto CCV's single finality_depth field, where
// zero selects finality-tag mode and a positive value selects confirmation-depth mode. Its error is
// a bare reason without the chain ID, which the caller prefixes when recording the skip.
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
			"uses confirmation-depth finality but has no FinalityDepth; set FinalityDepth or FinalityTagEnabled")
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
