# Replay

The replay module provides crash-recoverable data replay for the indexer. It re-fetches messages and CCV records from upstream sources to backfill missing data or overwrite stale records after bugs, deployments, or upstream outages.

## Why a Separate Process

The replay runs as a standalone binary (`indexer-replay`) rather than inside the live indexer process. This guarantees complete isolation from the main polling and worker threads:

- **Own OS process** — separate goroutines, memory, and connection pools. A long-running replay cannot starve the live traffic of CPU, memory, or database connections.
- **Own gRPC/REST connections** — replay creates its own aggregator and verifier readers with independent circuit breakers, so replay-induced load never trips the live readers.
- **Own DB connection pool** — configurable independently; defaults to lower limits than the live indexer.

## Why CLI over HTTP

Both the CLI and an HTTP endpoint share the same replay engine, so switching later is straightforward. The CLI was chosen as the primary interface because:

- **Security** — no endpoint to protect. Whoever has `kubectl exec` access to the pod already has the right authorization level. An HTTP endpoint would require auth middleware, RBAC, and abuse protection (concurrent replay limits, rate limiting).
- **Operational fit** — replays are long-running (minutes to hours). HTTP would require an async pattern (accept → 202 → poll for status), which is essentially a CLI with extra ceremony.
- **Kubernetes Jobs** — for large replays the CLI can be launched as a Kubernetes Job with resource limits, timeouts, and automatic restart on failure (see below).

## Replay Modes

### Discovery Replay

Re-discovers messages from the aggregator starting at a given sequence number and gathers their CCV records from all configured verifiers.

```
indexer-replay discovery --since 42
indexer-replay discovery --since 42 --force
```

The `--since` flag takes an aggregator sequence number (unsigned integer). All messages with a sequence number greater than or equal to the given value will be replayed.

Without `--force` the replay backfills only — existing messages and CCV records are left untouched (`ON CONFLICT DO NOTHING`). With `--force`, existing records are overwritten (`ON CONFLICT DO UPDATE`).

### Message Replay

Fetches CCV records from all configured verifiers for a specific set of message IDs. Does not re-run discovery.

```
indexer-replay messages --ids "0xabc123,0xdef456"
indexer-replay messages --ids "0xabc123,0xdef456" --force
```

### Job Management

```
indexer-replay status --id <job-uuid>   # show details for a single job
indexer-replay list                     # list recent replay jobs
indexer-replay resume --id <job-uuid>   # resume a failed/interrupted job
```

## Crash Recovery

Replay jobs are persisted in a `replay_jobs` Postgres table. If the process crashes or the pod restarts mid-replay:

1. **At-least-once checkpointing** — the progress cursor is periodically updated after replayed data is written. On a crash, the cursor may lag behind some already-committed rows, causing those rows to be replayed again, but no committed work is lost.
2. **Advisory locks** — a PostgreSQL session-level advisory lock prevents two processes from running the same job concurrently. The lock is automatically released when the connection drops (crash, pod eviction).
3. **Automatic resumption** — on restart the engine detects the stale `running` job (via heartbeat timeout), re-acquires the lock, and resumes from the last persisted cursor, potentially reprocessing some already-written rows.

## Running as a Kubernetes Job

For large replays it is recommended to run the CLI as a Kubernetes Job rather than via `kubectl exec`. This gives you automatic retries, resource limits, and timeout control.

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: indexer-replay-discovery
spec:
  backoffLimit: 3
  activeDeadlineSeconds: 7200   # 2 hour timeout
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: replay
          image: indexer:latest
          command:
            - /bin/indexer-replay
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
│      Live Indexer Process       │     │    Replay CLI Process            │
│                                 │     │                                  │
│  Discovery ──► Worker Pool      │     │  CLI ──► Engine                  │
│                 │               │     │            ├── DiscoveryReplayer │
│                 ▼               │     │            └── MessageReplayer   │
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
