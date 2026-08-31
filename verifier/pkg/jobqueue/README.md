# Job Queue System

## Overview

The Job Queue provides a durable, PostgreSQL-backed task queue with automatic retry, failure handling, and job archiving. It's designed for reliable message processing in the CCV verifier pipeline.

## Architecture

The queue consists of two main tables:
- **Active Table** (`ccv_task_verifier_jobs` / `ccv_storage_writer_jobs`): Contains jobs that are pending or currently being processed
- **Archive Table** (`*_archive`): Contains completed and failed jobs for audit purposes

## Job States

Jobs transition through the following states:

| State | Description |
|-------|-------------|
| `pending` | Job is waiting to be consumed by a worker |
| `processing` | Job is currently being processed by a worker |
| `completed` | Job finished successfully (exists only in archive) |
| `failed` | Job permanently failed (exists only in archive) |

**Important**: Only `pending` and `processing` jobs exist in the active table. Once a job is `completed` or `failed`, it is immediately moved to the archive table.

## State Machine Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                            ACTIVE TABLE                                │
│                                                                        │
│   ┌─────────┐                                                          │
│   │ Publish │                                                          │
│   └────┬────┘                                                          │
│        │                                                               │
│        v                                                               │
│   ┌─────────┐                ┌────────────┐                            │
│   │ pending │───Consume─────>│ processing │                            │
│   └─────────┘                └──────┬─────┘                            │
│        ^                            │                                  │
│        │                            │                                  │
│        │       Retry                │                                  │
│        │      (within        ┌──────┼────────┬──────────┐              │
│        │      deadline)      │      │        │          │              │
│        │                     v      v        v          v              │
│        └────────────────  Retry  Complete   Fail       Retry           │
│                                      │             (exceeded deadline) │
│                                      │             │                   │
│                                      │             │                   │
│                                      │             │                   │
└──────────────────────────────────────┼─────────────┼───────────────────┘
                                       │             │
                                       │             │
                                       v             v
                            ┌─────────────┐  ┌─────────────┐
                            │   Archive   │  │   Archive   │      
                            │ (completed) │  │   (failed)  │
                            └─────────────┘  └─────────────┘

                           ARCHIVE TABLE
```

## State Transitions

### 1. Publish → Pending

```go
err := queue.Publish(ctx, job1, job2, job3)
```

- Creates new jobs in `pending` state
- Sets `available_at` timestamp (default: immediate)
- Sets `retry_deadline` based on `RetryDuration` config
- Jobs become immediately available for consumption

### 2. Consume: Pending → Processing

The queue offers the two halves of consumption together or separately. Both use the same
SQL; only the scheduling differs.

```go
jobs, err := queue.Consume(ctx, batchSize)        // both halves, one shared budget

jobs, err := queue.ConsumePending(ctx, batchSize) // pending only, full budget
jobs, err := queue.ReclaimStale(ctx, batchSize)   // stale only, full budget
```

**`Consume` execution order (two queries, always both run):**
1. **Stale reclamation** — jobs in `processing` state where `started_at + LockDuration <= NOW()`, up to `batchSize`. Runs unconditionally so crashed-worker jobs are always reclaimed even under persistent pending backlog.
2. **Pending** — jobs in `pending` state where `available_at <= NOW()`, up to `batchSize - len(staleJobs)`. Fills the remaining capacity computed in memory from the stale result, so a full batch is returned whenever there are no stale jobs.

**`ConsumePending` and `ReclaimStale`** each run one of those queries with the full
`batchSize`. A consumer that drives the two halves on separate schedules uses these, so a
stale sweep can fill a batch of its own while a pending backlog is still waiting. See
[Waking a consumer](#waking-a-consumer).

**Effects (both paths):**
- Updates status to `processing`
- Sets `started_at` timestamp
- Increments `attempt_count`
- Locks the job using `FOR UPDATE SKIP LOCKED` (prevents duplicate consumption)

**Note**: Failed jobs are **NOT** consumed - they are archived and cannot be retried.

### 3. Complete: Processing → Archived (Completed)

```go
err := queue.Complete(ctx, jobID1, jobID2)
```

- Deletes jobs from active table
- Inserts into archive table with `completed` status
- Sets `completed_at` timestamp
- Creates permanent audit trail

### 4. Retry: Processing → Pending (or Archived if deadline exceeded)

```go
err := queue.Retry(ctx, delay, errorMap, jobID1, jobID2)
```

**If `NOW() < retry_deadline`:**
- Updates status to `pending`
- Sets `available_at = NOW() + delay`
- Records error message in `last_error`
- Job becomes available for retry after delay

**If `NOW() >= retry_deadline`:**
- Updates status to `failed`
- Records error message
- **Archives the job** (moves to archive table)
- Job will NOT be retried again

### 5. Fail: Processing → Archived (Failed)

```go
err := queue.Fail(ctx, errorMap, jobID1, jobID2)
```

- Updates status to `failed`
- Records error message in `last_error`
- **Immediately archives the job** (moves to archive table)
- Job will NOT be retried

## Key Invariant

**Every job consumed from the queue must eventually be:**
- **Completed** → archived with `completed` status
- **Failed** → archived with `failed` status
- **Retried** → returned to `pending` OR archived if retry deadline exceeded

This design ensures:
- ✅ Active table only contains pending/processing jobs
- ✅ No unbounded table growth
- ✅ Complete audit trail in archive
- ✅ Predictable resource usage

## Stale Lock Recovery

If a worker crashes while processing a job, the job remains in `processing` state. The queue always reclaims these "stale" jobs on the next `Consume` call regardless of how many pending jobs are waiting:

```
Worker A: Consume job → started_at = 10:00 AM → [CRASH]
Worker B: Consume (at 10:15 AM) → stale query runs first, detects started_at + LockDuration <= NOW()
Worker B: Reclaims job → attempt_count++, then fills remaining batch capacity with pending jobs
```

The stale query always executes first with the full `batchSize` limit. The pending query then uses the remaining capacity (`batchSize - staleCount`). This ordering guarantees stale jobs are never crowded out by a persistently backlogged pending queue.

**Configuration:**
- `LockDuration`: How long a job can stay in `processing` before being reclaimed (default: 1 minute)

A consumer that schedules the two halves separately sweeps for stale locks on its own
timer, because stale work is produced by the passage of time and no signal can announce
it. Worst-case reclaim is then `LockDuration` plus the sweep interval.

## Waking a consumer

The queue signals in process when it makes work available, so a consumer does not have to
poll for it. `PostgresJobQueue` and `ObservabilityDecorator` both implement:

```go
type SignalDrivenQueue[T Jobable] interface {
    Signals() <-chan struct{}
    ConsumePending(ctx context.Context, batchSize int) ([]Job[T], error)
    ReclaimStale(ctx context.Context, batchSize int) ([]Job[T], error)
}
```

`JobQueue[T]` is unchanged. A consumer obtains the capability by type assertion and falls
back to polling when the assertion fails or `Signals()` returns nil.

**The signal is a hint, never a record.** Every row stays reachable by a poll, so a signal
that is lost costs latency and never costs a job. Three rules follow from that:

1. **A consumer must keep a fallback poll.** Three producers create work without any
   in-process signal: a restart where `ON CONFLICT DO NOTHING` drops the re-published
   rows, the out-of-process `ccv job-queue reschedule` CLI, and any other process sharing
   the same `owner_id`.
2. **Signals coalesce.** The channel holds at most one token, so a burst of any size
   arrives as one wakeup. A consumer must therefore look again whenever its last look
   returned anything, or it will process one batch and wait for the fallback.
3. **Signals are sent after the transaction commits.** A signal sent from inside the
   transaction would wake a consumer that reads pre-commit state on another connection,
   finds nothing, and is never woken for those rows again.

`Publish` signals immediately. `PublishWithDelay` and `Retry` schedule the wake for when
the rows actually become available, so a short retry delay is not stretched out to the
fallback interval. `Complete`, `Fail` and `Cleanup` never signal, because none of them can
make a row pending.

## Configuration

```go
type QueueConfig struct {
    Name          string        // Queue name for logging and table naming
    OwnerID       string        // Scopes jobs so multiple verifiers can share tables
    RetryDuration time.Duration // How long jobs can be retried before permanent failure
    LockDuration  time.Duration // How long before a processing job is considered stale
}
```

## Usage Example

### Basic Flow

```go
// 1. Create queue
queue, err := jobqueue.NewPostgresJobQueue[MyJob](
    db,
    jobqueue.QueueConfig{
        Name:          "my_jobs",
        OwnerID:       "my-verifier",
        RetryDuration: time.Hour,
        LockDuration:  time.Minute,
    },
    logger,
)

// 2. Publish jobs
err = queue.Publish(ctx, job1, job2, job3)

// 3. Worker: Consume and process
jobs, err := queue.Consume(ctx, 10) // batch of up to 10 jobs
for _, job := range jobs {
    err := processJob(job)
    if err == nil {
        // Success - archive as completed
        queue.Complete(ctx, job.ID)
    } else if isTransientError(err) {
        // Transient error - retry after delay
        queue.Retry(ctx, 10*time.Second, map[string]error{job.ID: err}, job.ID)
    } else {
        // Permanent error - archive as failed
        queue.Fail(ctx, map[string]error{job.ID: err}, job.ID)
    }
}

// 4. Periodic cleanup of old archive entries
deleted, err := queue.Cleanup(ctx, 30*24*time.Hour) // delete after 30 days
```

### Delayed Publishing

```go
// Publish job that becomes available in 1 hour
err := queue.PublishWithDelay(ctx, time.Hour, job)
```

### Monitoring

```go
// Get count of pending + processing jobs
size, err := queue.Size(ctx)
log.Printf("Queue size: %d", size)
```

## Concurrency Guarantees

- **Multiple Publishers**: Safe - concurrent `Publish()` calls are isolated
- **Multiple Consumers**: Safe - `SELECT FOR UPDATE SKIP LOCKED` ensures no duplicate consumption
- **Concurrent Operations**: Safe - all operations use database transactions

### Retry Strategy Example

```go
func handleResult(queue JobQueue, job Job, err error) {
    if err == nil {
        queue.Complete(ctx, job.ID)
        return
    }
    
    // Check retry deadline
    if time.Now().After(job.RetryDeadline) {
        // Too late to retry - fail permanently
        queue.Fail(ctx, map[string]error{job.ID: err}, job.ID)
        return
    }
    
    // Classify error
    if isTransient(err) {
        // Exponential backoff based on attempt count
        delay := time.Duration(math.Pow(2, float64(job.AttemptCount))) * time.Second
        queue.Retry(ctx, delay, map[string]error{job.ID: err}, job.ID)
    } else {
        // Permanent error
        queue.Fail(ctx, map[string]error{job.ID: err}, job.ID)
    }
}
```