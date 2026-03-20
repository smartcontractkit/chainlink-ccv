package protocol

import (
	"context"
	"time"

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

// GetChainName resolves a human-readable chain name for the given selector
// using the remote chain-selectors cache. Falls back to "unknown:<selector>"
// when the selector cannot be resolved.
func GetChainName(selector ChainSelector) string {
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
