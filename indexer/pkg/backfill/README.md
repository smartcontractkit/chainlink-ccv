# Backfill

The backfill module provides crash-recoverable data backfill for the indexer. It re-fetches messages and CCV records from upstream sources to backfill missing data or overwrite stale records after bugs, deployments, or upstream outages.

> **Rename note:** this tool used to be called "replay" (`indexer-replay`, `indexer/pkg/replay`). It was renamed to "backfill" to avoid colliding with the verifier's unrelated message replay concept (re-verification of messages via `ccv jobqueue reschedule`). The Postgres table is still named `replay_jobs` — that name predates the rename and is kept for migration compatibility.

## Why a Separate Process

The backfill runs as a standalone binary (`indexer-backfill`) rather than inside the live indexer process. This guarantees complete isolation from the main polling and worker threads:

- **Own OS process** — separate goroutines, memory, and connection pools. A long-running backfill cannot starve the live traffic of CPU, memory, or database connections.
- **Own gRPC/REST connections** — backfill creates its own aggregator and verifier readers with independent circuit breakers, so backfill-induced load never trips the live readers.
- **Own DB connection pool** — configurable independently; defaults to lower limits than the live indexer.

## Why CLI over HTTP

Both the CLI and an HTTP endpoint share the same backfill engine, so switching later is straightforward. The CLI was chosen as the primary interface because:

- **Security** — no endpoint to protect. Whoever has `kubectl exec` access to the pod already has the right authorization level. An HTTP endpoint would require auth middleware, RBAC, and abuse protection (concurrent backfill limits, rate limiting).
- **Operational fit** — backfills are long-running (minutes to hours). HTTP would require an async pattern (accept → 202 → poll for status), which is essentially a CLI with extra ceremony.
- **Kubernetes Jobs** — for large backfills the CLI can be launched as a Kubernetes Job with resource limits, timeouts, and automatic restart on failure (see below).

## Backfill Modes

### Discovery Backfill

Re-discovers messages from the aggregator starting at a given sequence number and gathers their CCV records from all configured verifiers.

```
indexer-backfill discovery --since 42
indexer-backfill discovery --since 42 --force
```

The `--since` flag takes an aggregator sequence number (unsigned integer). All messages with a sequence number greater than or equal to the given value will be backfilled.

Without `--force` the backfill fills gaps only — existing messages and CCV records are left untouched (`ON CONFLICT DO NOTHING`). With `--force`, existing records are overwritten (`ON CONFLICT DO UPDATE`).

### Message Backfill

Fetches CCV records from all configured verifiers for a specific set of message IDs. Does not re-run discovery.

```
indexer-backfill messages --ids "0xabc123,0xdef456"
indexer-backfill messages --ids "0xabc123,0xdef456" --force
```

### Job Management

```
indexer-backfill status --id <job-uuid>   # show details for a single job
indexer-backfill list                     # list recent backfill jobs
indexer-backfill resume --id <job-uuid>   # resume a failed/interrupted job
```

## Crash Recovery

Backfill jobs are persisted in a `replay_jobs` Postgres table (the table name predates the backfill rename and is kept for migration compatibility). If the process crashes or the pod restarts mid-backfill:

1. **At-least-once checkpointing** — the progress cursor is periodically updated after backfilled data is written. On a crash, the cursor may lag behind some already-committed rows, causing those rows to be backfilled again, but no committed work is lost.
2. **Advisory locks** — a PostgreSQL session-level advisory lock prevents two processes from running the same job concurrently. The lock is automatically released when the connection drops (crash, pod eviction).
3. **Automatic resumption** — on restart the engine detects the stale `running` job (via heartbeat timeout), re-acquires the lock, and resumes from the last persisted cursor, potentially reprocessing some already-written rows.

## Running as a Kubernetes Job

For large backfills it is recommended to run the CLI as a Kubernetes Job rather than via `kubectl exec`. This gives you automatic retries, resource limits, and timeout control.

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: indexer-backfill-discovery
spec:
  backoffLimit: 3
  activeDeadlineSeconds: 7200   # 2 hour timeout
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: backfill
          image: indexer:latest
          command:
            - /bin/indexer-backfill
            - discovery
            - --since
            - "42"
          env:
            - name: INDEXER_CONFIG_PATH
              value: /etc/indexer/config.toml
          volumeMounts:
            - name: config
              mountPath: /etc/indexer
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              cpu: "1"
              memory: 512Mi
      volumes:
        - name: config
          configMap:
            name: indexer-config
```

With `restartPolicy: OnFailure` the pod is automatically restarted after a crash. On restart the engine finds the incomplete job, acquires the advisory lock, and continues from where it left off.

## Architecture

```
┌─────────────────────────────────┐     ┌──────────────────────────────────┐
│      Live Indexer Process       │     │   Backfill CLI Process           │
│                                 │     │                                  │
│  Discovery ──► Worker Pool      │     │  CLI ──► Engine                  │
│                 │               │     │            ├── DiscoveryBackfill │
│                 ▼               │     │            └── MessageBackfill   │
│             Scheduler           │     │                                  │
└────────┬────────────────────────┘     └───────┬──────────────────────────┘
         │                                      │
         │      ┌────────────────────┐          │
         ├─────►│   Postgres DB      │◄─────────┤
         │      │  (shared, separate │          │
         │      │   connection pools)│          │
         │      └────────────────────┘          │
         │                                      │
         │      ┌────────────────────┐          │
         ├─────►│  Aggregator gRPC   │◄─────────┤
         │      └────────────────────┘          │
         │                                      │
         │      ┌────────────────────┐          │
         └─────►│  Verifier Sources  │◄─────────┘
                └────────────────────┘
```
