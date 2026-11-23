# Indexer storage keeps the work state on each message

## Executive Summary

- `indexer.messages` gets the columns that a worker needs to claim, lease, retry and expire a message: `attempt_count`, `next_attempt_at`, `retry_deadline` and `trace_parent`. A partial index finds the due `PROCESSING` rows.
- `IndexerStorage` gets `ClaimWork`, `SettleWork`, `ExpireWork` and `CountProcessingMessages`. A later change moves the worker pool to these methods, so that all replicas share the work.
- This change is additive. The current worker does not call the new methods, and its behavior does not change.
- It affects `indexer/pkg/storage`, `indexer/pkg/common`, `indexer/pkg/monitoring` and two new migrations. It adds methods to two interfaces.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `common.IndexerStorage.ClaimWork`, `SettleWork`, `ExpireWork`, `CountProcessingMessages` | signature-changed | `IndexerStorage\b\|MessageStorageWriter\b` | `indexer/pkg/common/storage.go` | [#indexerstorage-has-work-state-methods](#indexerstorage-has-work-state-methods) |
| `common.IndexerMetricLabeler.RecordWorkerQueueSizeGauge` | signature-changed | `IndexerMetricLabeler\b` | `indexer/pkg/common/metrics.go` | [#metrics](#metrics) |
| `storage.PostgresStorage.UpsertMessages`, `PersistDiscoveryBatch` | behavior-changed | `\.UpsertMessages\(\|\.PersistDiscoveryBatch\(` | `indexer/pkg/storage/postgres.go` | [#message-insert-writes-trace_parent](#message-insert-writes-trace_parent) |
| `common.ErrClaimLost`, `common.WorkClaim`, `common.WorkSettlement` | added | `ErrClaimLost\|WorkClaim\|WorkSettlement` | `indexer/pkg/common/storage.go` | [#indexerstorage-has-work-state-methods](#indexerstorage-has-work-state-methods) |
| `common.MessageMetadata.TraceParent` | added | `Metadata\.TraceParent` | `indexer/pkg/common/metadata.go` | [#message-insert-writes-trace_parent](#message-insert-writes-trace_parent) |
| `storage.PostgresStorage.SetOnMessagesPersisted` | added | `SetOnMessagesPersisted\(` | `indexer/pkg/storage/postgres.go` | [#onmessagespersisted-callback](#onmessagespersisted-callback) |
| `indexer.messages` columns and `idx_messages_processing_due` | added | `indexer\.messages` | `indexer/migrations/postgres/20261123000000_messages_work_state.sql` | [#schema](#schema) |

## Breaking Changes

### IndexerStorage has work state methods

- **What changed:** `common.MessageStorageWriter` (part of `IndexerStorage`) adds four methods:
  - `ClaimWork(ctx, limit, lease, window)` leases up to `limit` due `PROCESSING` rows with `FOR UPDATE SKIP LOCKED`. It increments `attempt_count` and sets `next_attempt_at = NOW() + lease`. It skips rows that are past their deadline.
  - `SettleWork(ctx, WorkSettlement)` changes the row only when `status = 'PROCESSING'` and `attempt_count = Attempt`. Else it returns `common.ErrClaimLost`. A retry that starts at or after the deadline becomes `TIMEOUT`.
  - `ExpireWork(ctx, window, limit)` sets `TIMEOUT` on rows that are past their deadline and not leased.
  - `CountProcessingMessages(ctx)` returns the number of `PROCESSING` rows.
- The deadline is `COALESCE(retry_deadline, ingestion_timestamp + window)`. Postgres decides it with its own clock.
- `WorkClaim.Attempt` is the claim token. When a lease ends and another worker claims the row, the count goes up, so the first worker cannot settle it.
- **Who is affected:** All `IndexerStorage` implementations. In this repo they are `storage.PostgresStorage`, `storage.MetricsAwareStorage` and `mocks.MockIndexerStorage`. Regenerate mocks with `just mock`.

## Migration Guide

1. Add the four methods to custom `IndexerStorage` implementations.
2. Add `RecordWorkerQueueSizeGauge(ctx, size int64)` to custom `IndexerMetricLabeler` implementations.
3. Regenerate mocks: `just mock`.

## New Features / Additions

### Schema

- `20261123000000_messages_work_state.sql` adds these columns to `indexer.messages`:
  - `attempt_count INT NOT NULL DEFAULT 0`
  - `next_attempt_at TIMESTAMPTZ`
  - `retry_deadline TIMESTAMPTZ`
  - `trace_parent TEXT`
- `20261123000001_messages_due_idx.sql` adds `idx_messages_processing_due ON indexer.messages (next_attempt_at NULLS FIRST) WHERE status = 'PROCESSING'`.
- Existing rows need no backfill. A `PROCESSING` row with a NULL `next_attempt_at` is due now, and its deadline comes from `ingestion_timestamp`.

### Message insert writes trace_parent

The message insert has a ninth column, `trace_parent`. It writes `NULL` when `MessageMetadata.TraceParent` is empty. A forced upsert does not change `trace_parent`. Nothing sets the field yet.

### OnMessagesPersisted callback

`PostgresStorage.SetOnMessagesPersisted(fn)` sets a callback. `PersistDiscoveryBatch` calls it after a commit that has messages. Nothing sets the callback yet.

### Query plans

`work_state_explain_test.go` seeds 200,000 final rows and 6,500 `PROCESSING` rows. It writes the `EXPLAIN ANALYZE` plan of each work state query to `indexer/pkg/storage/testdata/explain_work_state_*.txt`. All queries use `idx_messages_processing_due` or the primary key. The SQL is in constants, so the test runs the same queries as the code.

## Metrics

- **Added:** `indexer_worker_queue_size`, the number of `PROCESSING` messages. Nothing records it yet.

## Compatibility & Requirements

- **Index build:** the index migration runs in a transaction. It blocks writes to `indexer.messages` and scans the full table. Deploy it with indexing paused. To estimate the pause, use the size of `indexer.messages`, or time the build on staging.
- **Rollback:** the old image runs on the new schema. It does not read the new columns, and the insert defaults fill them.
