package protocol

import (
	"context"
	"sync"
	"time"

	chainselectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chain-selectors/remote"
)

var chainSelectorOpts = []remote.Option{
	remote.WithTimeout(1 * time.Second),
	remote.WithCacheTTL(4 * time.Hour),
}

// unknownSelectorTTL controls how long we suppress remote retries for selectors
// that were not found in either local static data or the remote dataset.
// This prevents repeated HTTP calls (and 1 s timeout blocks) on hot paths when
// a selector is genuinely absent or GitHub is temporarily unreachable.
const unknownSelectorTTL = 10 * time.Minute

type chainNameEntry struct {
	name     string
	unknown  bool      // true when the name is the "unknown:<sel>" fallback
	cachedAt time.Time // set only when unknown == true; used to enforce TTL
}

var (
	chainNameCache   = make(map[uint64]chainNameEntry)
	chainNameCacheMu sync.RWMutex
	initCacheOnce    sync.Once
)

// InitChainSelectorCache warms up the remote chain-selectors cache by
// fetching the full selector list from GitHub. Selector 0 is intentionally
// invalid, so the lookup itself is expected to fail — the side-effect of
// populating the shared cache is what matters.
// Call this once during service boot.
func InitChainSelectorCache() {
	initCacheOnce.Do(func() {
		_, _ = remote.GetChainDetailsBySelector(context.Background(), 0, chainSelectorOpts...)
	})
}

// GetChainName resolves a human-readable chain name for the given selector.
// Lookup order:
//  1. Per-selector result cache (in-process) — O(1), no network.
//  2. Local static data compiled into the binary — O(1), no network.
//  3. Remote cache (4h TTL) or live GitHub fetch — only for selectors absent from the binary.
//
// "Unknown" results are cached for unknownSelectorTTL so that a genuinely absent
// selector or a GitHub outage does not cause repeated HTTP calls on hot paths.
// Falls back to "unknown:<selector>" when the selector cannot be resolved at any layer.
func GetChainName(selector ChainSelector) string {
	sel := uint64(selector)

	// 1. Per-selector result cache.
	chainNameCacheMu.RLock()
	entry, hit := chainNameCache[sel]
	chainNameCacheMu.RUnlock()
	if hit {
		if !entry.unknown || time.Since(entry.cachedAt) < unknownSelectorTTL {
			return entry.name
		}
		// Unknown entry expired — fall through to re-resolve.
	}

	// 2. Local static lookup — covers all chains compiled into this library version.
	if name, err := chainselectors.GetChainNameFromSelector(sel); err == nil {
		chainNameCacheMu.Lock()
		chainNameCache[sel] = chainNameEntry{name: name}
		chainNameCacheMu.Unlock()
		return name
	}

	// 3. Remote cache / live fetch for selectors not in the static dataset.
	name := "unknown:" + selector.String()
	unknown := true
	if details, err := remote.GetChainDetailsBySelector(context.Background(), sel, chainSelectorOpts...); err == nil {
		name = details.ChainName
		unknown = false
	}

	chainNameCacheMu.Lock()
	chainNameCache[sel] = chainNameEntry{name: name, unknown: unknown, cachedAt: time.Now()}
	chainNameCacheMu.Unlock()
	return name
}
