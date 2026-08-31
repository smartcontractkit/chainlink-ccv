# Signal-driven job queue wakeup

## Executive Summary

- The two verifier job queue consumers now wait for an in-process signal instead of polling every 500 ms, and keep a slow poll only as a liveness net.
- The 500 ms poll floor was a fixed cost that did not depend on message traffic. Across a fleet sharing one database it was large enough to starve the node's own subsystems.
- Affects `verifier/pkg/jobqueue`, `verifier/pkg/taskverifier` and `verifier/pkg/storagewriter`.
- `JobQueue[T]` gains three methods. No SQL changed, no schema changed, and there is no feature flag: the new behavior is the only behavior and a rollback is a plain binary swap.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `taskverifier.NewProcessorWithPollInterval` | removed | `NewProcessorWithPollInterval\(` | — | [#polling-removed](#polling-removed) |
| `storagewriter.NewProcessorWithPollInterval` | removed | `NewProcessorWithPollInterval\(` | — | [#polling-removed](#polling-removed) |
| `jobqueue.JobQueue.Consume` | removed | `\.Consume\(` | — | [#jobqueue-method-set-changed](#jobqueue-method-set-changed) |
| `jobqueue.JobQueue` | signature-changed | `jobqueue\.JobQueue\[` | `verifier/pkg/jobqueue/interface.go:51` | [#jobqueue-method-set-changed](#jobqueue-method-set-changed) |
| `taskverifier.NewProcessor` | signature-changed | `taskverifier\.NewProcessor\(` | `verifier/pkg/taskverifier/processor.go:105` | [#polling-removed](#polling-removed) |
| `storagewriter.NewProcessor` | signature-changed | `storagewriter\.NewProcessor\(` | `verifier/pkg/storagewriter/processor.go:99` | [#polling-removed](#polling-removed) |
| `jobqueue.PostgresJobQueue.Publish` | behavior-changed | `\.Publish\(` | `verifier/pkg/jobqueue/postgres_queue.go:74` | [#signals](#signals) |
| `jobqueue.PostgresJobQueue.Retry` | behavior-changed | `\.Retry\(` | `verifier/pkg/jobqueue/postgres_queue.go:472` | [#signals](#signals) |
| `jobqueue.PostgresJobQueue.ConsumePending` | added | `\.ConsumePending\(` | `verifier/pkg/jobqueue/postgres_queue.go:207` | [#split-consumption](#split-consumption) |
| `jobqueue.PostgresJobQueue.ReclaimStale` | added | `\.ReclaimStale\(` | `verifier/pkg/jobqueue/postgres_queue.go:228` | [#split-consumption](#split-consumption) |
| `jobqueue.PostgresJobQueue.Signals` | added | `\.Signals\(` | `verifier/pkg/jobqueue/postgres_queue.go:70` | [#signals](#signals) |

## Breaking Changes

### JobQueue method set changed

- **What changed:** `Consume` is replaced by `ConsumePending`, `ReclaimStale` and `Signals`.
- **Before:** 9 methods, with `Consume` running both queries under one shared `batchSize` budget.
- **After:** 11 methods. Each half takes the full `batchSize`.
- **Why:** the two halves are driven differently. Pending work is announced by a signal; stale work is produced only by the passage of time and must be swept on a timer. Keeping `Consume` would have left a method nothing calls. Putting the three methods on the one interface, rather than behind an optional capability obtained by type assertion, also removes a failure mode: a decorator forwarding some methods but not others would have silently pushed every consumer back to polling.
- **Who is affected:** anything calling `Consume` or implementing `JobQueue[T]` by hand.

### NewProcessorWithPollInterval removed

- **What changed:** both processor packages lost `NewProcessorWithPollInterval`, and `NewProcessor` gained a trailing `opts ...Option`.
- **Why:** there is only one loop now, so a constructor named after polling would describe something that no longer exists.
- **Who is affected:** callers wanting a short timer in tests.

## Migration Guide

1. Replace `Consume` with the half you need. A consumer that only wants available work uses `ConsumePending`; recovering crashed workers uses `ReclaimStale` on a timer.

2. Hand-written `JobQueue[T]` implementations drop `Consume` and add three methods. A producer-only fake can return zero values:

```go
func (q *fakeQueue) ConsumePending(context.Context, int) ([]jobqueue.Job[T], error) { return nil, nil }
func (q *fakeQueue) ReclaimStale(context.Context, int) ([]jobqueue.Job[T], error)   { return nil, nil }
func (q *fakeQueue) Signals() <-chan struct{}                                        { return nil }
```

3. Replace the removed constructor with the option:

```go
// Before
NewProcessorWithPollInterval(lggr, id, ..., 50*time.Millisecond)

// After
NewProcessor(lggr, id, ..., WithPendingFallbackInterval(50*time.Millisecond))
```

## Polling removed

`run` goes straight into the signal loop. `forcePolling`, `runPolling`, `processBatch` and the mode-selection block are gone, as is the now-unread `pollInterval` field.

The loop selects over: the signal, a pending re-arm, a 30 s pending fallback ticker, a stale re-arm, a 2 min stale sweep, and the unchanged 4 h cleanup ticker.

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
2. **Coalescing.** The channel holds at most one token, so a burst of any size arrives as one wakeup. The consumer re-arms whenever a batch came back full, which is what drains a burst without spending an empty query on every arrival.
3. **Three producers signal nothing:** a restart where `ON CONFLICT DO NOTHING` drops the re-published rows, the out-of-process `ccv job-queue reschedule` CLI, and any other process sharing the same `owner_id`. The fallback poll is what covers them.

## Split consumption

`Consume` is removed. It combined both queries under one shared `batchSize` budget, and nothing calls it now that the two halves run on separate schedules.

`ConsumePending` and `ReclaimStale` run one of those queries each with the full `batchSize`. Stale reclamation runs on its own timer because stale work is produced by the passage of time and no signal can announce it. Worst-case reclaim becomes `LockDuration` plus the sweep interval: 4 minutes for the task queue and 3 minutes for the result queue, against roughly 2 and 1 minutes before.

## Compatibility & Requirements

- **Feature flags / rollout:** none. There is no new job-spec key on purpose: `bootstrap/job.go` rejects a standalone job on undecoded keys, so a new key would stop an older binary from starting.
- **Rollback:** a binary swap. No schema change, no SQL change, and no persisted state differs between the two modes.
- **Canary signal:** watch `verifier_verification_queue_latency_seconds`. Its p50 should **fall**. A p50 climbing towards the fallback interval means the signal path is not reaching the consumer.
