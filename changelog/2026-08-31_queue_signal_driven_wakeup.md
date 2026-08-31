# Signal-driven job queue wakeup

## Executive Summary

- The verifier job queue now signals its consumer in process when work becomes available, instead of the consumer polling every 500 ms.
- The poll floor was a fixed cost that did not depend on message traffic. Across a fleet sharing one database it was large enough to starve the node's own subsystems, which is what this removes.
- Affects `verifier/pkg/jobqueue`, `verifier/pkg/taskverifier` and `verifier/pkg/storagewriter`.
- `JobQueue[T].Consume` is replaced by `ConsumePending`, `ReclaimStale` and `Signals`. No SQL changed and no schema changed, so a rollback is a plain binary swap.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `jobqueue.JobQueue.Consume` | removed | `\.Consume\(` | — | [#jobqueue-method-set](#jobqueue-method-set) |
| `taskverifier.NewProcessorWithPollInterval` | removed | `NewProcessorWithPollInterval\(` | — | [#processor-constructors](#processor-constructors) |
| `storagewriter.NewProcessorWithPollInterval` | removed | `NewProcessorWithPollInterval\(` | — | [#processor-constructors](#processor-constructors) |
| `taskverifier.NewProcessor` | signature-changed | `taskverifier\.NewProcessor\(` | `verifier/pkg/taskverifier/processor.go:98` | [#processor-constructors](#processor-constructors) |
| `storagewriter.NewProcessor` | signature-changed | `storagewriter\.NewProcessor\(` | `verifier/pkg/storagewriter/processor.go:94` | [#processor-constructors](#processor-constructors) |
| `jobqueue.PostgresJobQueue.Publish` | behavior-changed | `\.Publish\(` | `verifier/pkg/jobqueue/postgres_queue.go:73` | [#signals](#signals) |
| `jobqueue.PostgresJobQueue.PublishWithDelay` | behavior-changed | `\.PublishWithDelay\(` | `verifier/pkg/jobqueue/postgres_queue.go:78` | [#signals](#signals) |
| `jobqueue.PostgresJobQueue.Retry` | behavior-changed | `\.Retry\(` | `verifier/pkg/jobqueue/postgres_queue.go:426` | [#signals](#signals) |
| `jobqueue.JobQueue.ConsumePending` | added | `\.ConsumePending\(` | `verifier/pkg/jobqueue/interface.go:64` | [#jobqueue-method-set](#jobqueue-method-set) |
| `jobqueue.JobQueue.ReclaimStale` | added | `\.ReclaimStale\(` | `verifier/pkg/jobqueue/interface.go:69` | [#jobqueue-method-set](#jobqueue-method-set) |
| `jobqueue.JobQueue.Signals` | added | `\.Signals\(` | `verifier/pkg/jobqueue/interface.go:80` | [#signals](#signals) |
| `jobqueue.DefaultPendingFallbackInterval` | added | `DefaultPendingFallbackInterval\b` | `verifier/pkg/jobqueue/signal.go:11` | [#signals](#signals) |
| `taskverifier.Option` | added | `taskverifier\.Option\b` | `verifier/pkg/taskverifier/processor.go:43` | [#processor-constructors](#processor-constructors) |
| `storagewriter.Option` | added | `storagewriter\.Option\b` | `verifier/pkg/storagewriter/processor.go:43` | [#processor-constructors](#processor-constructors) |
| `taskverifier.WithPendingFallbackInterval` | added | `WithPendingFallbackInterval\(` | `verifier/pkg/taskverifier/processor.go:46` | [#processor-constructors](#processor-constructors) |
| `taskverifier.WithStaleReclaimInterval` | added | `WithStaleReclaimInterval\(` | `verifier/pkg/taskverifier/processor.go:55` | [#processor-constructors](#processor-constructors) |
| `storagewriter.WithPendingFallbackInterval` | added | `WithPendingFallbackInterval\(` | `verifier/pkg/storagewriter/processor.go:46` | [#processor-constructors](#processor-constructors) |
| `storagewriter.WithStaleReclaimInterval` | added | `WithStaleReclaimInterval\(` | `verifier/pkg/storagewriter/processor.go:55` | [#processor-constructors](#processor-constructors) |

## Breaking Changes

### JobQueue method set

- **What changed:** `Consume` is replaced by `ConsumePending`, `ReclaimStale` and `Signals`.
- **Before:** `Consume(ctx, batchSize)` ran the stale query then the pending query under one shared `batchSize` budget.
- **After:** each half is its own method taking the full `batchSize`.
- **Why:** the two halves are driven differently. Pending work is announced by a signal, so a consumer can wait for it. Stale work is produced only by the passage of time, so nothing can announce it and a consumer must sweep for it on a timer. Once they run on separate schedules the combined call has no caller.
- **Who is affected:** anything calling `Consume`, and anything implementing `JobQueue[T]` by hand.

### NewProcessorWithPollInterval removed

- **What changed:** both processor packages lost `NewProcessorWithPollInterval`; `NewProcessor` gained a trailing `opts ...Option`.
- **Before:** the constructor set the 500 ms consume ticker, and existed so tests could shorten it.
- **After:** there is no consume ticker to set. `WithPendingFallbackInterval` shortens the fallback poll instead, which is what a test actually wants.
- **Who is affected:** callers of that constructor. Adding a variadic parameter to `NewProcessor` is source-compatible with every existing call.

## Migration Guide

1. Replace `Consume` with the half you need:

```go
// Before
jobs, err := queue.Consume(ctx, batchSize)

// After — work that is available now
jobs, err := queue.ConsumePending(ctx, batchSize)
// After — locks held past LockDuration, on a timer
jobs, err := queue.ReclaimStale(ctx, batchSize)
```

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

## Signals

The signal is a hint, never a record. Every row stays reachable by `ConsumePending`, so a signal that is lost costs latency and never costs a job.

| Method | Signals? |
|---|---|
| `Publish` | yes, immediately, after the transaction commits |
| `PublishWithDelay` | yes, scheduled for the delay |
| `Retry` | yes, scheduled for the delay, and only for jobs that went back to `pending` |
| `Complete`, `Fail`, `Cleanup`, `Size`, both consume paths | no — none can make a row pending |

Three properties matter for anyone building on this:

1. **Sent after commit.** A signal from inside the transaction would wake a consumer that reads pre-commit state on another pooled connection, finds nothing, and is never woken for those rows again.
2. **Coalescing.** The channel holds at most one token, so a burst of any size arrives as one wakeup. A consumer must therefore look again whenever a batch came back full, or the rest of the burst waits for the fallback.
3. **Three producers signal nothing:** a restart where `ON CONFLICT DO NOTHING` drops the re-published rows, the out-of-process `ccv job-queue reschedule` CLI, and any other process sharing the same `owner_id`. This is why a consumer must keep a fallback poll; `DefaultPendingFallbackInterval` is 30 s.

`Retry` schedules its wake for when the rows actually become available rather than firing immediately, so a 2 s retry delay stays 2 s instead of stretching to the fallback interval.

## Processor constructors

Both processors wait on the signal, with a 30 s fallback poll for pending work and a 2 min sweep for stale locks. Neither has a consume ticker any more.

```go
// unchanged call, now signal-driven
p, err := storagewriter.NewProcessor(lggr, id, mon, tracker, storage, queue, cfg)

// options exist so a test does not wait on production intervals
p, err := storagewriter.NewProcessor(lggr, id, mon, tracker, storage, queue, cfg,
    storagewriter.WithPendingFallbackInterval(50*time.Millisecond),
    storagewriter.WithStaleReclaimInterval(200*time.Millisecond),
)
```

## Stale reclamation timing

Stale locks are now swept on their own 2 min timer rather than on every consume, so worst-case reclaim becomes `LockDuration` plus the sweep interval: 4 minutes for the task queue and 3 minutes for the result queue, against roughly 2 and 1 minutes before. This path is not only crash recovery — the task verifier also routes `Publish`, `Complete` and `Retry` failures into it.

## Compatibility & Requirements

- **Feature flags / rollout:** none. There is no new job-spec key on purpose: `bootstrap/job.go` rejects a standalone job on undecoded keys, so a new key would stop an older binary from starting.
- **Rollback:** a binary swap. No schema change, no SQL change, and no persisted state differs between the old and new consumption modes.
- **Canary signal:** watch `verifier_verification_queue_latency_seconds`. Its p50 should **fall**. A p50 climbing towards the fallback interval means the signal is not reaching the consumer.
