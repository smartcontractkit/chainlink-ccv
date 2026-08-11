# Align standalone cutover behavior with Chainlink-node production

## Executive Summary

- Standalone executor NTP retry timing and message retention now match CL-mode production behavior.
- Streamers defensively normalize a zero query limit so an empty response cannot cause a busy loop.
- Verifier database-open errors and two operator-facing configuration diagnostics are corrected.
- CL-mode defaulting and finality-checker semantics, plus current explicit production behavior, are
  unchanged.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `ccvstreamer.NewIndexerStorageStreamer` | behavior-changed | `NewIndexerStorageStreamer\(` | `integration/pkg/ccvstreamer/indexer_storage_streamer.go:40` | [Zero query limits](#zero-query-limits) |
| `executor.Factory.Start` | behavior-changed | `func \(f \*Factory\) Start` | `cmd/executor/service.go:87` | [Shared executor timing](#shared-executor-timing) |
| `verifier.ConnectToPostgresDB` | behavior-changed | `ConnectToPostgresDB\(` | `cmd/verifier/common.go:76` | [Database errors](#database-errors) |
| `executor.MessageContextWindow` | added | `MessageContextWindow\b` | `executor/config.go:27` | [Shared executor timing](#shared-executor-timing) |
| `executor.NTPBackoffDuration` | added | `NTPBackoffDuration\b` | `executor/config.go:29` | [Shared executor timing](#shared-executor-timing) |

## Breaking Changes

No breaking changes.

## Behavior Changes

### Zero query limits

`ccvstreamer.NewIndexerStorageStreamer` normalizes a zero `QueryLimit` to
`executor.IndexerQueryLimitDefault`. Requests and the pagination comparison therefore use the same
effective limit, and an empty successful response waits for `PollingInterval` instead of
immediately querying again.

### Shared executor timing

Standalone now uses the CL-mode values exposed as `executor.NTPBackoffDuration` (2s), independent of
indexer request backoff, and `executor.MessageContextWindow` (24h) for streamer duplicate retention.
The CL constructor consumes the same constants without changing its effective behavior.

### Database errors

`ConnectToPostgresDB` returns a wrapped `sql.Open` error instead of returning a nil data source and
nil error. Callers already propagate its error result and require no signature change.

## Compatibility & Requirements

- No dependency or configuration-schema changes.
- CL-mode executor defaulting and finality-checker behavior are unchanged.
- The missing-executor-ID diagnostic now names the actual TOML key, `executor_id`.
