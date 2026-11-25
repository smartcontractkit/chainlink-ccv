# Indexer workers claim messages from Postgres on all replicas

## Executive Summary

- The worker pool runs on every replica and claims due `PROCESSING` rows from `indexer.messages` with `ClaimWork`. The in-memory scheduler, the heap, the discovery channel and the hydrate are removed.
- Before this change, only the leader held the work in memory. A crash or a leader change lost the backoff state, and after a leader change two replicas could do the same work.
- This change affects `indexer/pkg/worker`, `indexer/pkg/discovery`, `indexer/pkg/storage`, `indexer/pkg/config` and `indexer/cmd`.
- It has breaking changes to Go interfaces and constructors. It adds one config field and deprecates three.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `common.IndexerStorage.GetProcessingMessages` | removed | `\.GetProcessingMessages\(` | — | [#getprocessingmessages-removed](#getprocessingmessages-removed) |
| `worker.Scheduler`, `worker.NewScheduler`, `worker.Pool.Hydrate` | removed | `NewScheduler\(\|\.Hydrate\(` | — | [#scheduler-and-hydrate-removed](#scheduler-and-hydrate-removed) |
| `discovery.WithOnElected` | removed | `WithOnElected\(` | — | [#scheduler-and-hydrate-removed](#scheduler-and-hydrate-removed) |
| `common.MessageDiscovery.Start` | signature-changed | `\.Start\(ctx\)` | `indexer/pkg/common/discovery.go:14` | [#messagediscovery-start-returns-nothing](#messagediscovery-start-returns-nothing) |
| `worker.NewWorkerPool` | signature-changed | `NewWorkerPool\(` | `indexer/pkg/worker/worker_pool.go:75` | [#newworkerpool-signature](#newworkerpool-signature) |
| `worker.NewTask` | signature-changed | `NewTask\(` | `indexer/pkg/worker/task.go` | [#newworkerpool-signature](#newworkerpool-signature) |
| `discovery.AggregatorMessageDiscovery` trace parent | behavior-changed | `TraceParent` | `indexer/pkg/discovery/message_discovery.go` | [#discovery-hands-off-through-the-database](#discovery-hands-off-through-the-database) |
| `config.SchedulerConfig.TickerInterval`, `MaxHeapSize`, `config.PoolConfig.HydrationBatchSize` | deprecated | `TickerInterval\|MaxHeapSize\|HydrationBatchSize` | `indexer/pkg/config/config.go` | [#deprecations](#deprecations) |
| `RecordVerificationRecordChannelSizeGauge` | deprecated | `RecordVerificationRecordChannelSizeGauge\(` | `indexer/pkg/common/metrics.go` | [#metrics](#metrics) |
| `worker.Pool.Wake`, `SetLeadership`, `SetSizeRecorder`, `worker.LeaderChecker` | added | `\.Wake\(\)\|SetLeadership\(\|SetSizeRecorder\(` | `indexer/pkg/worker/worker_pool.go:110` | [#newworkerpool-signature](#newworkerpool-signature) |
| `config.PoolConfig.PollInterval` | added | `PollInterval` | `indexer/pkg/config/config.go:174` | [#new-features--additions](#new-features--additions) |

## Breaking Changes

### GetProcessingMessages removed

- **What changed:** `IndexerStorage.GetProcessingMessages` is removed from the interface, `PostgresStorage` and `MetricsAwareStorage`.
- **Why:** Only the hydrate used it. `ClaimWork` replaces it.

### Scheduler and Hydrate removed

- **What changed:** `worker/scheduler.go`, `worker/heap.go`, `Pool.Hydrate`, `Pool.enqueueMessages`, `handleDLQ`, the `Task` scheduler fields (`runAt`, heap index, `ttl`, `lastErr`, `traceParent`), `Task.SetMessageStatus` and `discovery.WithOnElected` are removed.
- **Why:** The row in `indexer.messages` holds the retry state. A new leader has no state to load.
- **Who is affected:** Code that builds a `Scheduler` or calls `Hydrate`. Remove the calls.

### MessageDiscovery.Start returns nothing

- **Before:** `Start(ctx) chan VerifierResultWithMetadata`. The pool read the channel.
- **After:** `Start(ctx)`. Discovery writes the messages as `PROCESSING` rows, and the pool claims them.

### NewWorkerPool signature

- **Before:** `NewWorkerPool(logger, config.PoolConfig, discoveryChannel, *Scheduler, registry, storage)`
- **After:** `NewWorkerPool(lggr, config.PoolConfig, config.SchedulerConfig, registry, storage)`
- `NewTask` has no `ttl` argument now. The deadline is in the database.

```go
pool, err := worker.NewWorkerPool(lggr, cfg.Pool, cfg.Scheduler, registry, store)
pool.SetLeadership(elector)                               // expire runs on the leader only
pool.SetSizeRecorder(metrics.RecordWorkerQueueSizeGauge)
dbStore.SetOnMessagesPersisted(pool.Wake)                 // claim at once after a discovery commit
```

## Migration Guide

1. Remove all `Scheduler`, `Hydrate` and `WithOnElected` calls.
2. Change `NewWorkerPool` and `NewTask` calls to the new signatures.
3. Wire `SetLeadership`, `SetSizeRecorder` and `SetOnMessagesPersisted` as in the example above.
4. Do not read a channel from `MessageDiscovery.Start`.
5. Regenerate mocks: `just mock`.

## New Features / Additions

### Worker pool

- Each replica claims at most one message for each free worker slot. It claims when `Wake` is called and on each `PollInterval` tick.
- A claim leases the row for `WorkerTimeout + 30s`. When a replica stops, another replica claims the row after the lease ends.
- After each attempt the worker settles the row:

  | Result | Settle |
  |---|---|
  | All verifications collected | `SUCCESSFUL` |
  | Some verifications are missing, or an error | Retry after `BackoffDelay(attempt)`. The database sets `TIMEOUT` when the retry starts after the deadline. |
  | Error that cannot be recovered (for example, a missing message) | `TIMEOUT` |

- A settle that returns `ErrClaimLost` is logged at debug level. Another worker has the row.
- The leader runs `ExpireWork` once a minute in its own goroutine, in batches of 1,000. It then records `indexer_worker_queue_size`.

### Discovery hands off through the database

- Discovery opens the per-verification spans before the persist. `setMessageTraceParents` stores the first traceparent of each message in `trace_parent`. The worker loads it, so the worker span is a child of the discovery span.
- After the commit, `PersistDiscoveryBatch` calls `pool.Wake`.
- `MultiSourceMessageDiscovery` only starts and stops the sources. The message primary key and `ON CONFLICT DO NOTHING` make one row for a message that more sources find.

### Config

- **`[Pool] PollInterval`** — the milliseconds between two claims when no wake signal comes. Default 1000.

## Deprecations

- **`[Scheduler] TickerInterval`, `[Scheduler] MaxHeapSize`, `[Pool] HydrationBatchSize`** — they have no effect. Old configs still load. Remove them from the deploy configs, then from the code.

## Metrics

- **Recorded:** `indexer_worker_queue_size` (added in the work state change). The leader records it after each expire run.
- **Deprecated:** `indexer_verification_record_channel_size`. It stays registered but has no data. Move dashboards and vm-alerts to `indexer_worker_queue_size` before you remove it.

## Compatibility & Requirements

- **Requires:** the work state migrations (`2026-11-23_indexer_message_work_state.md`).
- **Message replay:** this change does not change the replay. A discovery replay writes `PROCESSING` rows, and the workers claim them. A message replay fetches the verifications but does not change the status. A later change makes it requeue the message.
- **Mixed versions:** an old replica that is the leader keeps its in-memory retries, and the new replicas claim the same rows. The work is done twice for a short time, but the data stays correct: an old `TIMEOUT` changes only a `PROCESSING` row, and a new settle needs the claim token.
