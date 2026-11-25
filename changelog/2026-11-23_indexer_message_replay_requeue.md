# Indexer message replay puts messages back in the worker queue

## Executive Summary

- `indexer-replay messages` now sets each message that is not `SUCCESS` back to `PROCESSING` with a new deadline of now + `VerificationVisibilityWindow`. The live workers then fetch the missing verifications, retry with backoff and set the final status.
- Before this change, the replay fetched the verifications itself and did not change the status. A message with the status `TIMEOUT` stayed `TIMEOUT`, and the workers did not retry it.
- This change affects `indexer/pkg/replay`, `indexer/cmd/replay` and `indexer/pkg/storage`.
- It adds a method to `replay.Storage` and a required engine option for message replays.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `replay.Storage.RequeueMessages` | signature-changed | `replay\.Storage\b\|\.RequeueMessages\(` | `indexer/pkg/replay/engine.go` | [#replay-storage-has-requeuemessages](#replay-storage-has-requeuemessages) |
| `replay.Engine` message replay | behavior-changed | `runMessageReplay\|indexer-replay messages` | `indexer/pkg/replay/message_replay.go` | [#message-replay-requeues](#message-replay-requeues) |
| `replay.WithRetryWindow` | added | `WithRetryWindow\(` | `indexer/pkg/replay/engine.go:48` | [#replay-storage-has-requeuemessages](#replay-storage-has-requeuemessages) |
| `storage.PostgresStorage.RequeueMessages` | added | `\.RequeueMessages\(` | `indexer/pkg/storage/work_state.go` | [#message-replay-requeues](#message-replay-requeues) |

## Breaking Changes

### Replay Storage has RequeueMessages

- **What changed:** `replay.Storage` adds `RequeueMessages(ctx, ids []protocol.Bytes32, window time.Duration) ([]protocol.Bytes32, error)`. A message replay needs `replay.WithRetryWindow(d)`. Without it, a message replay returns `retry window not configured`.
- **Who is affected:** Custom `replay.Storage` implementations and code that builds a `replay.Engine` for message replays. `indexer/cmd/replay` passes `WithRetryWindow(VerificationVisibilityWindow)`.

## Migration Guide

1. Add `RequeueMessages` to custom `replay.Storage` implementations.
2. Add `replay.WithRetryWindow(time.Duration(cfg.Scheduler.VerificationVisibilityWindow) * time.Second)` to `replay.NewEngine`.

## New Features / Additions

### Message replay requeues

- `RequeueMessages` changes each given row that is not `SUCCESS`:
  - It sets `status = 'PROCESSING'`, clears `lastErr` and sets `retry_deadline = NOW() + window`.
  - A `PROCESSING` row keeps its lease and its `attempt_count`. Only its deadline changes.
  - A final row (`TIMEOUT`) gets `attempt_count + 1` and a NULL `next_attempt_at`, so it is due now. The new count stops an old claim from settling the reopened row.
- It returns the IDs that it changed and wakes the local pool. A message that is `SUCCESS` or not found is logged and skipped.
- Without `--force`, the replay only requeues. The workers fetch only the missing verifications.
- With `--force`, the replay first fetches the verifications from all configured verifiers and overwrites the stored ones, then requeues.
- `work_state_explain_test.go` adds the plan of the requeue query. It uses the primary key.

## Compatibility & Requirements

- **Requires:** the worker claim change (`2026-11-23_indexer_workers_claim_messages.md`).
- **Discovery replay:** no change. It writes `PROCESSING` rows, and the workers claim them.
