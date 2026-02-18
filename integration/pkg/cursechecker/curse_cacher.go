package cursechecker

import (
	"context"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// We use 100 entries for the curse cache because we're bounded by number of source chains.
const curseCacheMaxEntries = 100

// CachedCurseChecker is a wrapper around the RMNCurseReader that caches the curse state for each destination chain.
// It uses an LRU cache to store the curse state for each destination chain.
type CachedCurseChecker struct {
	lggr       logger.Logger
	metrics    common.CurseCheckerMetrics
	rmnReaders map[protocol.ChainSelector]chainaccess.RMNCurseReader
	// Cache of curse state per destination chain.
	// The cache key is a destination chain selector, the cache value is a set of bytes16curse subjects (including global curse).
	curseCache *expirable.LRU[protocol.ChainSelector, cacheValue]
}

// cacheValue is the set of Bytes16 curse subjects for a chain. It can be either a Bytes16 ChainSelector or the GlobalCurseSubject.
// We store this as Bytes16 instead of protocol.ChainSelector to cleanly handle the Global Curse Subject (represented in Bytes16).
type cacheValue map[protocol.Bytes16]struct{}

type Params struct {
	Lggr        logger.Logger
	Metrics     common.CurseCheckerMetrics
	RmnReaders  map[protocol.ChainSelector]chainaccess.RMNCurseReader
	CacheExpiry time.Duration
}

// NewCachedCurseChecker creates a new CachedCurseChecker.
func NewCachedCurseChecker(params Params) CachedCurseChecker {
	curseCache := expirable.NewLRU[protocol.ChainSelector, cacheValue](curseCacheMaxEntries, nil, params.CacheExpiry)
	return CachedCurseChecker{
		lggr:       params.Lggr,
		metrics:    params.Metrics,
		rmnReaders: params.RmnReaders,
		curseCache: curseCache,
	}
}

// IsRemoteChainCursed checks if the remote chain is cursed for the local chain.
func (c CachedCurseChecker) IsRemoteChainCursed(ctx context.Context, localChain, remoteChain protocol.ChainSelector) bool {
	cursedSubjects := make(map[protocol.Bytes16]struct{})
	// Use Peek instead of Get to avoid refreshing the cache entry.
	curseInfo, found := c.curseCache.Peek(localChain)
	if found {
		c.lggr.Debugf("curse state retrieved from cache for dest chain %d with subjects %v",
			localChain, curseInfo)

		return c.isChainSelectorCursed(ctx, curseInfo, localChain, remoteChain)
	}

	curseResults, err := c.rmnReaders[localChain].GetRMNCursedSubjects(ctx)
	if err != nil {
		c.lggr.Errorw("Failed to get cursed subjects, assuming not cursed", "error", err)
		return false
	}

	for _, subject := range curseResults {
		cursedSubjects[subject] = struct{}{}
		// curse metric lifts off with next execution in `isChainSelectorCursed` call
		if subject == GlobalCurseSubject {
			c.metrics.SetLocalChainGlobalCursed(ctx, localChain, true)
		} else if subject == ChainSelectorToBytes16(remoteChain) {
			c.metrics.SetRemoteChainCursed(ctx, localChain, remoteChain, true)
		}
	}

	c.curseCache.Add(localChain, cursedSubjects)
	return c.isChainSelectorCursed(ctx, cursedSubjects, localChain, remoteChain)
}

// isChainSelectorCursed checks if the remote chain is cursed for the local chain.
// It converts from a protocol.ChainSelector to a Bytes16 and checks if it is in the cursedSubjects set.
// It also checks if the GlobalCurseSubject is in the cursedSubjects set.
func (c CachedCurseChecker) isChainSelectorCursed(ctx context.Context, cursedSubjects cacheValue, localChain, remoteChain protocol.ChainSelector) bool {
	_, hasGlobalCurse := cursedSubjects[GlobalCurseSubject]
	_, remoteChainCursed := cursedSubjects[ChainSelectorToBytes16(remoteChain)]

	c.metrics.SetLocalChainGlobalCursed(ctx, localChain, hasGlobalCurse)
	c.metrics.SetRemoteChainCursed(ctx, localChain, remoteChain, remoteChainCursed)

	return hasGlobalCurse || remoteChainCursed
}
