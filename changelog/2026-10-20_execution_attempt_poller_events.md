# Execution-attempt poller event handling

## Executive Summary

- The EVM execution-attempt poller's cursor tracking, replay handling, and subscription reconnect behavior were tightened in `integration/pkg/destinationreader/evm_execution_attempt_poller.go`.
- `lastPolledBlock` now advances in WebSocket mode (previously only HTTP paths moved it), so reconnects resume near the chain tip instead of from the startup position.
- Replayed events after a resubscription are deduplicated, and a reconnect no longer starts an additional event-consumer goroutine.
- Behavior changes only; all touched symbols are unexported, so downstream consumers need no migration.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `destinationreader.EvmExecutionAttemptPoller` event handling | behavior-changed | `NewEVMExecutionAttemptPoller\(` | `integration/pkg/destinationreader/evm_execution_attempt_poller.go:145` | [#poller-behavior](#poller-behavior) |

## Breaking Changes

*No breaking changes.*

## Poller behavior

- `lastPolledBlock` is now an `atomic.Uint64` advanced by
  `EvmExecutionAttemptPoller.advanceLastPolledBlock` (forward-only) at the end of every
  successful `processExecutionStateChanged`
  (`integration/pkg/destinationreader/evm_execution_attempt_poller.go:789`), in both WS and
  HTTP modes; `pollForEvents` still stores `toBlock` at the end of each poll to cover
  ranges with no events. `reconnectSubscription` therefore resumes from the latest
  processed event's block rather than the stale startup position.
- `processExecutionStateChanged` skips events already present in the new `seenEvents`
  LRU (key = 32-byte tx hash + 4-byte log index, built by `eventKey`, TTL matched to the
  attempt cache, capped at 10,000 entries), so an event replayed by a resubscription is
  not appended to the attempt cache twice.
- `run` is started exactly once, in `startWSMode`, and consumes `eventCh` for the service
  lifetime; a successful `handleReconnection` now restarts only `monitorSubscription`.
- `subscription` reads/writes (`startWSMode`, `monitorSubscription`,
  `reconnectSubscription`, `Close`) are guarded by the new `subMu` mutex, and `Close`
  cancels the run context before unsubscribing so reconnect backoff exits on context
  done first; `runWg.Wait()` remains last.
