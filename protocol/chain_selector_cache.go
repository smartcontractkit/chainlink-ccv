package protocol

import (
	"context"
	"time"

	chainselectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chain-selectors/remote"
)

var chainSelectorOpts = []remote.Option{
	remote.WithTimeout(1 * time.Second),
	remote.WithCacheTTL(4 * time.Hour),
}

// InitChainSelectorCache warms up the remote chain-selectors cache by
// fetching the full selector list from GitHub. Selector 0 is intentionally
// invalid, so the lookup itself is expected to fail — the side-effect of
// populating the shared cache is what matters.
// Call this once during service boot.
func InitChainSelectorCache() {
	_, _ = remote.GetChainDetailsBySelector(context.Background(), 0, chainSelectorOpts...)
}

// GetChainName resolves a human-readable chain name for the given selector.
// Lookup order:
//  1. Local static data compiled into the binary — zero latency, no network.
//  2. Remote cache (4h TTL populated by InitChainSelectorCache) — no network when warm.
//  3. Live HTTP fetch from GitHub — only when the cache is cold or expired.
//
// Falls back to "unknown:<selector>" when the selector cannot be resolved at any layer.
func GetChainName(selector ChainSelector) string {
	// 1. Local static lookup — covers all chains shipped with the library version.
	if name, err := chainselectors.GetChainNameFromSelector(uint64(selector)); err == nil {
		return name
	}

	// 2 & 3. Remote cache, then live fetch for selectors not in the static dataset.
	details, err := remote.GetChainDetailsBySelector(
		context.Background(),
		uint64(selector),
		chainSelectorOpts...,
	)
	if err != nil {
		return "unknown:" + selector.String()
	}
	return details.ChainName
}
