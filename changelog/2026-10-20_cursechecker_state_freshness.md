# Curse checker state freshness

## Executive Summary

- `integration/pkg/cursechecker` now bounds the age of cached RMN curse state: poll state older than `stalenessMultiplier * pollInterval` (10 intervals; 100s at the 10s default) is treated as unknown.
- `PollerService.IsRemoteChainCursed` and `CachedCurseChecker.IsRemoteChainCursed` return `(true, common.ErrCurseStateUnknown)` whenever curse state cannot be determined (never polled, stale, missing reader, or RPC failure), so the lane is blocked until state is refreshed.
- `NewCachedCurseChecker` applies a 5-minute default cache expiry when `Params.CacheExpiry <= 0`, matching the executor's standalone default.
- Behavior changes only; no exported signatures changed, so downstream consumers need no migration.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `cursechecker.PollerService.IsRemoteChainCursed` | behavior-changed | `\.IsRemoteChainCursed\(` | `integration/pkg/cursechecker/curse_poller.go:131` | [#poller-state-freshness](#poller-state-freshness) |
| `cursechecker.CachedCurseChecker.IsRemoteChainCursed` | behavior-changed | `\.IsRemoteChainCursed\(` | `integration/pkg/cursechecker/curse_cacher.go:62` | [#cacher-missing-reader](#cacher-missing-reader) |
| `cursechecker.ChainCurseState.UpdatedAt` | added | `ChainCurseState\{` | `integration/pkg/cursechecker/curse_poller.go:37` | [#poller-state-freshness](#poller-state-freshness) |
| `cursechecker.defaultCurseCacheExpiry` | added | `CacheExpiry` | `integration/pkg/cursechecker/curse_cacher.go:20` | [#cacher-default-expiry](#cacher-default-expiry) |

## Breaking Changes

*No breaking changes.*

## Poller state freshness

- `ChainCurseState` gains an `UpdatedAt` field, set only when a poll of that chain's RMN Remote succeeds (`integration/pkg/cursechecker/curse_poller.go:201`).
- `IsRemoteChainCursed` returns `(true, common.ErrCurseStateUnknown)` when `time.Since(state.UpdatedAt) > stalenessMultiplier * s.pollInterval` (`curse_poller.go:145`), the same result as the never-polled path. `stalenessMultiplier` is an unexported constant (10), so the threshold is 100s at the default 10s poll interval; `NewCurseDetectorService`'s signature is unchanged.
- The poll loop logs a Warn once per chain when its cached state crosses the staleness threshold during a failure streak (`PollerService.notePollFailure`, `curse_poller.go:234`); the flag resets on the next successful poll, so repeated failures do not repeat the log line.

## Cacher missing reader

- When `rmnReaders` has no entry for the queried local chain, `CachedCurseChecker.IsRemoteChainCursed` now returns `(true, common.ErrCurseStateUnknown)` (`curse_cacher.go:72-76`), identical to the RPC-failure path. The constructor wiring already adds one reader per enabled destination chain, so a miss indicates the chain is no longer configured.

## Cacher default expiry

- `Params.CacheExpiry <= 0` now resolves to the new package constant `defaultCurseCacheExpiry` (5 minutes) inside `NewCachedCurseChecker` (`curse_cacher.go:45-50`), matching the executor's `readerCacheExpiryDefault`. Callers that set a positive expiry are unaffected.

## References

- Stacked on: `changelog/2026-10-20_execution_attempt_poller_events.md`
