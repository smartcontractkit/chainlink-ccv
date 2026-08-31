package evmconfig

import (
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
)

// EffectiveChain is the curated projection of one chain's effective standalone configuration:
// what the process will actually run after chain-specific chainlink-evm defaults and CCV's
// overrides are applied. It exists for the pre-cutover settings diff (`ccv migrate
// inspect-config`): the conversion's warnings list what the node config set that standalone
// drops, and this projection shows what standalone runs instead.
//
// RPC URLs are deliberately absent: they can carry API keys, and a diff needs the redundancy
// picture (names, order, WebSocket coverage), not the endpoints.
type EffectiveChain struct {
	ChainID            string `json:"chain_id"`
	FinalityDepth      uint32 `json:"finality_depth"`
	FinalityTagEnabled bool   `json:"finality_tag_enabled"`
	// TXMBlockTime and NewHeadsPollInterval are duration strings ("12s"): this report is read by
	// a human running a diff, not by another program.
	TXMBlockTime string `json:"txm_block_time"`
	// TXMBlockTimeIsDefault is true when the operator set no block time and the 2-second
	// fallback fired — the value to check first on a slow chain before a cutover.
	TXMBlockTimeIsDefault  bool            `json:"txm_block_time_is_default"`
	HeadTrackerPersistence bool            `json:"head_tracker_persistence"`
	NewHeadsPollInterval   string          `json:"new_heads_poll_interval,omitempty"`
	Nodes                  []EffectiveNode `json:"nodes"`
}

// EffectiveNode is one RPC node's projection: identity and selection priority, never its URLs.
type EffectiveNode struct {
	Name         string `json:"name"`
	HasWebSocket bool   `json:"has_websocket"`
	Order        *int32 `json:"order,omitempty"`
}

// EffectiveChainConfigs resolves every chain in cfg against chainlink-evm's chain-specific
// defaults through the same BuildChainlinkEVMTOML the runtime adapter uses, so the report cannot
// drift from what the standalone process will run. It makes no network calls.
func EffectiveChainConfigs(cfg Config) (map[string]EffectiveChain, error) {
	infos, err := cfg.ToInfos()
	if err != nil {
		return nil, err
	}
	out := make(map[string]EffectiveChain, len(infos))
	for selector, info := range infos {
		tomlConfig, err := BuildChainlinkEVMTOML(info)
		if err != nil {
			return nil, err
		}
		out[selector] = projectEffectiveChain(info, tomlConfig)
	}
	return out, nil
}

func projectEffectiveChain(info Info, tomlConfig *evmtoml.EVMConfig) EffectiveChain {
	chain := tomlConfig.Chain
	projected := EffectiveChain{
		ChainID:                info.ChainID,
		TXMBlockTimeIsDefault:  info.TXMBlockTime == 0,
		HeadTrackerPersistence: chain.HeadTracker.PersistenceEnabled != nil && *chain.HeadTracker.PersistenceEnabled,
		FinalityTagEnabled:     chain.FinalityTagEnabled != nil && *chain.FinalityTagEnabled,
		Nodes:                  make([]EffectiveNode, 0, len(tomlConfig.Nodes)),
	}
	if chain.FinalityDepth != nil {
		projected.FinalityDepth = *chain.FinalityDepth
	}
	if chain.Transactions.TransactionManagerV2.BlockTime != nil {
		projected.TXMBlockTime = chain.Transactions.TransactionManagerV2.BlockTime.Duration().String()
	}
	if interval := chain.NodePool.NewHeadsPollInterval; interval != nil && interval.Duration() != 0 {
		projected.NewHeadsPollInterval = interval.Duration().String()
	}
	for _, node := range tomlConfig.Nodes {
		if node == nil {
			continue
		}
		entry := EffectiveNode{HasWebSocket: node.WSURL != nil, Order: node.Order}
		if node.Name != nil {
			entry.Name = *node.Name
		}
		projected.Nodes = append(projected.Nodes, entry)
	}
	return projected
}
