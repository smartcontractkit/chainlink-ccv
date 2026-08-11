# Align Chainlink-node and standalone cutover behavior

## Executive Summary

- CL-mode executors now apply the same documented defaults as standalone executors.
- Streamer query-limit handling, NTP retry timing, message retention, and finality-checker disabling
  no longer change behavior across the cutover boundary.
- Verifier database-open errors and two operator-facing configuration diagnostics are corrected.
- Existing explicit production configuration remains compatible; omitted executor tuning is now
  normalized instead of retaining unsafe zero values.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `constructors.NewExecutorCoordinator` | behavior-changed | `NewExecutorCoordinator\(` | `integration/pkg/constructors/executor.go:45` | [Executor defaults](#executor-defaults) |
| `ccvstreamer.NewIndexerStorageStreamer` | behavior-changed | `NewIndexerStorageStreamer\(` | `integration/pkg/ccvstreamer/indexer_storage_streamer.go:40` | [Zero query limits](#zero-query-limits) |
| `constructors.NewVerificationCoordinator` | behavior-changed | `NewVerificationCoordinator\(` | `integration/pkg/constructors/committee_verifier.go:39` | [Finality-checker parity](#finality-checker-parity) |
| `verifier.ConnectToPostgresDB` | behavior-changed | `ConnectToPostgresDB\(` | `cmd/verifier/common.go:76` | [Database errors](#database-errors) |
| `executor.MessageContextWindow` | added | `MessageContextWindow\b` | `executor/config.go:27` | [Shared executor timing](#shared-executor-timing) |
| `executor.NTPBackoffDuration` | added | `NTPBackoffDuration\b` | `executor/config.go:29` | [Shared executor timing](#shared-executor-timing) |

## Breaking Changes

No breaking changes.

## Behavior Changes

### Executor defaults

`constructors.NewExecutorCoordinator` calls `Configuration.GetNormalizedConfig` before constructing
its dependencies. Omitted tuning now resolves to the documented defaults: 15s source backoff, 1h
lookback, 100-message query limit, 5m reader-cache expiry, 8h retry window, 1s data-not-ready retry,
100 workers, `time.google.com`, and a 1m per-chain execution interval.

### Zero query limits

`ccvstreamer.NewIndexerStorageStreamer` normalizes a zero `QueryLimit` to
`executor.IndexerQueryLimitDefault`. Requests and the pagination comparison therefore use the same
effective limit, and an empty successful response waits for `PollingInterval` instead of
immediately querying again.

### Shared executor timing

Both executor modes use `executor.NTPBackoffDuration` (2s), independent of indexer request backoff,
and `executor.MessageContextWindow` (24h) for streamer duplicate retention.

### Finality-checker parity

The CL verifier constructor now maps `commit.Config.DisableFinalityCheckers` into each source
chain's `SourceConfig.DisableFinalityChecker`, matching the standalone verifier.

### Database errors

`ConnectToPostgresDB` returns a wrapped `sql.Open` error instead of returning a nil data source and
nil error. Callers already propagate its error result and require no signature change.

## Compatibility & Requirements

- No dependency or configuration-schema changes.
- Explicit executor tuning retains its configured values.
- The missing-executor-ID diagnostic now names the actual TOML key, `executor_id`.
