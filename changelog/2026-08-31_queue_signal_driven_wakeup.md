# Signal-driven job queue wakeup

## Executive Summary

- The two verifier job queue consumers now wait for an in-process signal instead of polling every 500 ms, and keep a slow poll only as a liveness net.
- Idle database load fell about 40x in measurement. The 500 ms poll floor was a fixed cost that did not depend on message traffic, and across a fleet sharing one database it was large enough to starve the node's own subsystems.
- Affects `verifier/pkg/jobqueue`, `verifier/pkg/taskverifier`, `verifier/pkg/storagewriter` and `verifier/pkg/coordinator.go`. `JobQueue[T]` is unchanged, so any external consumer keeps working untouched.
- Adds an optional capability interface. No SQL changed, no schema changed, and there is no feature flag: the new behavior is on by default and a rollback is a plain binary swap.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `taskverifier.NewProcessor` | signature-changed | `taskverifier\.NewProcessor\(` | `verifier/pkg/taskverifier/processor.go:105` | [#processor-constructors](#processor-constructors) |
| `storagewriter.NewProcessor` | signature-changed | `storagewriter\.NewProcessor\(` | `verifier/pkg/storagewriter/processor.go:101` | [#processor-constructors](#processor-constructors) |
| `jobqueue.PostgresJobQueue.Publish` | behavior-changed | `\.Publish\(` | `verifier/pkg/jobqueue/postgres_queue.go:52` | [#signals](#signals) |
| `jobqueue.PostgresJobQueue.Retry` | behavior-changed | `\.Retry\(` | `verifier/pkg/jobqueue/postgres_queue.go:370` | [#signals](#signals) |
| `verifier.queueObservabilityInterval` | behavior-changed | `queueObservabilityInterval` | `verifier/pkg/coordinator.go:38` | [#queue-size-metric-interval](#queue-size-metric-interval) |
| `jobqueue.SignalDrivenQueue` | added | `SignalDrivenQueue\b` | `verifier/pkg/jobqueue/signal.go:83` | [#signaldrivenqueue](#signaldrivenqueue) |
| `jobqueue.PostgresJobQueue.ConsumePending` | added | `\.ConsumePending\(` | `verifier/pkg/jobqueue/postgres_queue.go:190` | [#split-consumption](#split-consumption) |
| `jobqueue.PostgresJobQueue.ReclaimStale` | added | `\.ReclaimStale\(` | `verifier/pkg/jobqueue/postgres_queue.go:211` | [#split-consumption](#split-consumption) |
| `jobqueue.JitteredTicker` | added | `JitteredTicker\b` | `verifier/pkg/jobqueue/ticker.go:20` | [#jitter](#jitter) |
| `testutil.NewTestDBWithStats` | added | `NewTestDBWithStats\b` | `verifier/testutil/test_db_stats.go:30` | [#load-measurement](#load-measurement) |
| `testutil.DBLoadRecorder` | added | `DBLoadRecorder\b` | `verifier/testutil/db_load.go:47` | [#load-measurement](#load-measurement) |

## Breaking Changes

*No breaking changes.* `JobQueue[T]`, `QueueConfig`, `Job[T]` and every existing queue method keep their signatures and behavior. Both processor constructors gained a trailing variadic parameter, which is source-compatible with every existing call.

## Migration Guide

No action is required. The new behavior is on by default.

A consumer that wants the previous polling behavior keeps using `NewProcessorWithPollInterval`, which is unchanged and now explicitly forces the polling loop.

## Processor constructors

`NewProcessor` gained a trailing `opts ...Option` parameter in both processor packages, and now selects the signal-driven loop.

```go
// Before — polls every 500ms
p, err := storagewriter.NewProcessor(lggr, id, mon, tracker, storage, queue, cfg)
```

```go
// After — identical call, now signal-driven; options are only needed to retune the timers
p, err := storagewriter.NewProcessor(lggr, id, mon, tracker, storage, queue, cfg,
    storagewriter.WithPendingFallbackInterval(30*time.Second),
    storagewriter.WithStaleReclaimInterval(2*time.Minute),
)
```

`NewProcessorWithPollInterval` is unchanged and forces the legacy loop, so every existing test call site keeps the behavior it was written against.

## SignalDrivenQueue

`JobQueue[T]` is untouched. The new capability is obtained by type assertion:

```go
type SignalDrivenQueue[T Jobable] interface {
    Signals() <-chan struct{}
    ConsumePending(ctx context.Context, batchSize int) ([]Job[T], error)
    ReclaimStale(ctx context.Context, batchSize int) ([]Job[T], error)
}
```

`PostgresJobQueue` and `ObservabilityDecorator` both implement it, and a compile-time
assertion in `signal.go` keeps the decorator forwarding. A consumer must treat **both** a
failed assertion and a nil `Signals()` as "not supported" and fall back to polling.

## Signals

The signal is a hint, never a record. Every row stays reachable by a poll, so a signal that is lost costs latency and never costs a job.

| Method | Signals? |
|---|---|
| `Publish` | yes, immediately, after the transaction commits |
| `PublishWithDelay` | yes, scheduled for the delay |
| `Retry` | yes, scheduled for the delay, and only for jobs that went back to `pending` |
| `Complete`, `Fail`, `Cleanup`, `Size`, all consume paths | no — none can make a row pending |

Three properties matter for anyone building on this:

1. **Sent after commit.** A signal from inside the transaction would wake a consumer that reads pre-commit state on another pooled connection, finds nothing, and is never woken for those rows again.
2. **Coalescing.** The channel holds at most one token, so a burst of any size arrives as one wakeup. A consumer must look again whenever its last look returned anything.
3. **Three producers signal nothing:** a restart where `ON CONFLICT DO NOTHING` drops the re-published rows, the out-of-process `ccv job-queue reschedule` CLI, and any other process sharing the same `owner_id`. The fallback poll is what covers them.

## Split consumption

`Consume` is unchanged: it still runs the stale query then the pending query under one shared `batchSize` budget, with the same SQL.

`ConsumePending` and `ReclaimStale` run one of those queries each with the full `batchSize`. Stale reclamation moves onto its own timer because stale work is produced by the passage of time and no signal can announce it. Worst-case reclaim becomes `LockDuration` plus the sweep interval: 4 minutes for the task queue and 3 minutes for the result queue, against roughly 2 and 1 minutes before.

## Jitter

`JitteredTicker` varies each period by ±10%. A fleet restarted in a rolling deploy would otherwise phase-align on identical fixed periods and hit the shared database in one synchronized burst.

## Queue size metric interval

`queueObservabilityInterval` moved from 10 s to 60 s. Each tick runs one `COUNT(*)` per queue. Once the consumers stopped polling, that count became the largest remaining source of idle database work, and it is also the query that was timing out at 2 s in production. Queue depth changes slowly enough that a minute still shows a backlog forming.

## Load measurement

`testutil.NewTestDBWithStats` starts Postgres with `pg_stat_statements` preloaded, and `testutil.DBLoadRecorder` samples statement counts, index scans and commits over a dedicated connection using deltas rather than any reset. `NewTestDB` is deliberately untouched, so a missing contrib module can only skip the one test that needs it.

Measured by `Test_QueueLoad_AB`, both arms run one at a time on a shared container at scaled intervals (50 ms against 3 s, the same 1:60 ratio that ships as 500 ms against 30 s):

| Scenario | Polling | Signal-driven |
|---|---|---|
| Idle | 39.7 statements/s | 1.0 statements/s (**39.7x fewer**) |
| Burst of 100 jobs | 0.30 statements/job, drained in 518 ms | 0.22 statements/job, drained in 20 ms |
| Steady light traffic | 2.75 statements/job | 1.80 statements/job |

Assertions are on ratios, never absolute counts, so they hold on any machine.

## Compatibility & Requirements

- **Feature flags / rollout:** none. The behavior is on by default. There is no new job-spec key on purpose: `bootstrap/job.go` rejects a standalone job on undecoded keys, so a new key would stop an older binary from starting.
- **Rollback:** a binary swap. No schema change, no SQL change, and no persisted state differs between the two modes.
- **Canary signal:** watch `verifier_verification_queue_latency_seconds`. Its p50 should **fall**. A p50 climbing towards the fallback interval means the signal path is not reaching the consumer.

## Testing notes

- `TestExplainQueryPlans` now asserts plan structure (`requirePlan`) instead of only logging, and writes `testdata/explain_*.txt` only under `UPDATE_EXPLAIN_PLANS`. It previously rewrote nine tracked files on every run.
- Any new test that inserts rows directly, bypassing `Publish`, gets no signal and must set a short `WithPendingFallbackInterval`, or it will wait for the full fallback.
- Results whose `MessageID` derives from a sequence number must use distinct sequence numbers per publish, or the fake writer's map collapses them and a count can never be reached.
