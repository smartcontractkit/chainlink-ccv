# Aggregator orphan recovery runs on one replica at a time

## Executive Summary

- The aggregator orphan recoverer now takes a Postgres advisory lock before each scan. Only one replica scans at a time.
- Before this change, each replica scanned the full table and triggered `CheckAggregation` for each orphan. With N replicas, the database load and the aggregation checks were N times larger than necessary.
- This change affects the aggregator only: `aggregator/pkg/common`, `aggregator/pkg/storage/postgres`, `aggregator/pkg/model` and `aggregator/pkg`.
- It has small breaking changes to Go interfaces and signatures. It adds one config field with a default and one metric.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `common.CommitVerificationStore.TryAcquireOrphanRecoveryLock` | signature-changed | `CommitVerificationStore\b` | `aggregator/pkg/common/storage.go:36` | [#commitverificationstore-has-a-new-method](#commitverificationstore-has-a-new-method) |
| `common.AggregatorMetricLabeler.IncrementOrphanRecoverySkipped` | signature-changed | `AggregatorMetricLabeler\b` | `aggregator/pkg/common/metrics.go:61` | [#aggregatormetriclabeler-has-a-new-method](#aggregatormetriclabeler-has-a-new-method) |
| `aggregator.OrphanRecoverer.RecoverOrphans` | signature-changed | `\.RecoverOrphans\(` | `aggregator/pkg/orphan_recoverer.go:110` | [#recoverorphans-returns-a-scanned-flag](#recoverorphans-returns-a-scanned-flag) |
| `postgres.NewDatabaseStorage` | signature-changed | `postgres\.NewDatabaseStorage\(` | `aggregator/pkg/storage/postgres/database_storage.go:87` | [#newdatabasestorage-takes-a-postgresdatasource](#newdatabasestorage-takes-a-postgresdatasource) |
| `model.AggregatorConfig.ValidateOrphanRecoveryConfig` | behavior-changed | `orphanRecovery\]\|scanTimeout` | `aggregator/pkg/model/config.go:947` | [#new-config-validation](#new-config-validation) |
| `postgres.DataSource` | added | `\bpostgres\.DataSource\b` | `aggregator/pkg/storage/postgres/database_storage.go:62` | [#newdatabasestorage-takes-a-postgresdatasource](#newdatabasestorage-takes-a-postgresdatasource) |
| `postgres.DatabaseStorage.TryAcquireOrphanRecoveryLock` | added | `TryAcquireOrphanRecoveryLock\(` | `aggregator/pkg/storage/postgres/database_storage.go:916` | [#orphan-recovery-lock](#orphan-recovery-lock) |
| `model.OrphanRecoveryConfig.LockReleaseMargin` | added | `lockReleaseMargin\|LockReleaseMargin` | `aggregator/pkg/model/config.go:231` | [#orphan-recovery-lock](#orphan-recovery-lock) |
| `aggregator_orphan_recovery_skipped` | added | `aggregator_orphan_recovery_skipped` | `aggregator/pkg/monitoring/metrics.go:228` | [#metrics](#metrics) |

## Breaking Changes

### CommitVerificationStore has a new method

- **What changed:** `common.CommitVerificationStore` has the new method `TryAcquireOrphanRecoveryLock`.
- **Before:** The interface had no lock method.
- **After:** `TryAcquireOrphanRecoveryLock(ctx context.Context, idleTimeout time.Duration) (release func(), acquired bool, err error)`.
- **Why:** The orphan recoverer gets the lock through the store.
- **Who is affected:** All implementations of the interface. In this repo they are `postgres.DatabaseStorage`, `storage.MetricsAwareStorage` and `mocks.MockCommitVerificationStore`.

### AggregatorMetricLabeler has a new method

- **What changed:** `common.AggregatorMetricLabeler` has the new method `IncrementOrphanRecoverySkipped(ctx context.Context)`.
- **Why:** It counts the scans that a replica skips because a different replica holds the lock.
- **Who is affected:** All implementations. In this repo they are `monitoring.AggregatorMetricLabeler`, `monitoring.NoopAggregatorMetricLabeler` and `mocks.MockAggregatorMetricLabeler`.

### RecoverOrphans returns a scanned flag

- **What changed:** `OrphanRecoverer.RecoverOrphans`.
- **Before:** `RecoverOrphans(ctx context.Context) error`
- **After:** `RecoverOrphans(ctx context.Context) (scanned bool, err error)`
- **Why:** The caller must know if the scan ran or if the replica skipped it. A skipped scan returns `false, nil`. A skipped scan does not record a value in `aggregator_orphan_recovery_duration_seconds`.
- **Who is affected:** Direct callers. In this repo, only `OrphanRecoverer.Start` and tests call it.

### NewDatabaseStorage takes a postgres.DataSource

- **What changed:** The `ds` parameter of `postgres.NewDatabaseStorage` and the `DatabaseStorage.ds` field.
- **Before:** `sqlutil.DataSource`
- **After:** `postgres.DataSource`, which is `sqlutil.DataSource` plus `Conn(ctx context.Context) (*sql.Conn, error)`.
- **Why:** The session-level advisory lock needs a dedicated connection. A wrong client is now a compile error, not a runtime error.
- **Who is affected:** Callers that pass a type with no `Conn` method. `*sqlx.DB` already satisfies the interface, so no caller in this repo changed.

### New config validation

- **What changed:** When `orphanRecovery.enabled = true`, `ValidateOrphanRecoveryConfig` has two new rules:
  - `lockReleaseMargin` must be greater than 0.
  - `scanTimeout + lockReleaseMargin` must be less than `interval`.
- **Why:** If a replica stops, the database frees the lock after `scanTimeout + lockReleaseMargin`. This time must be shorter than the scan interval.
- **Who is affected:** Configs where `scanTimeout` is close to or greater than `interval`. The staging, prod-testnet and prod-mainnet configs use `interval = "5m"` and `scanTimeout = "4m"`. With the default margin of 30s, they stay valid.

## Migration Guide

1. Add `TryAcquireOrphanRecoveryLock` to custom `CommitVerificationStore` implementations.
2. Add `IncrementOrphanRecoverySkipped` to custom `AggregatorMetricLabeler` implementations.
3. Regenerate mocks: `just mock`.
4. Change direct calls of `RecoverOrphans`:

```go
// Before
err := recoverer.RecoverOrphans(ctx)
```

```go
// After
scanned, err := recoverer.RecoverOrphans(ctx)
```

5. Make sure that each aggregator config with orphan recovery enabled satisfies `scanTimeout + lockReleaseMargin < interval`.

## New Features / Additions

### Orphan recovery lock

- **Lock:** At the start of each scan, the recoverer calls `pg_try_advisory_lock(hashtextextended('aggregator_orphan_recovery', 0))` on a dedicated connection. It does not wait for the lock. If a different replica holds the lock, the replica skips the scan and tries again at the next `interval`. A skip is not an error, so the health check stays OK.
- **Normal release:** The release function runs `pg_advisory_unlock` and `RESET idle_session_timeout`, then returns the connection to the pool. If one of these queries fails, the connection is closed and not returned to the pool. Closing the session frees the lock.
- **Stuck scan:** When `scanTimeout` expires, `context.AfterFunc` releases the lock, also if the scan goroutine is stuck.
- **Stopped process:** Before the lock query, the lock connection sets `idle_session_timeout` to `scanTimeout + lockReleaseMargin`. The connection sends no queries while it holds the lock. If the process freezes or the pod stops, Postgres closes the session and frees the lock.
- **New config field:** `orphanRecovery.lockReleaseMargin` (`time.Duration`, default `30s`).

```toml
[orphanRecovery]
  enabled = true
  interval = "5m"
  scanTimeout = "4m"
  lockReleaseMargin = "30s"
```

### Metrics

- Added the counter `aggregator_orphan_recovery_skipped`, with the label `component=orphan_recoverer`. It counts the scans that a replica skips because a different replica holds the lock.
- No metric was removed or renamed.
- Only the replica that holds the lock updates `aggregator_orphan_backlog` and `aggregator_orphan_expired_backlog`. The other replicas keep the value from the last scan that they ran. Use `max(...)` across pods for these gauges. The devenv dashboard already does this.

## Compatibility & Requirements

- **Postgres:** Version 14 or later, because `idle_session_timeout` is a Postgres 14 setting. On an older version, each lock attempt fails, and the orphan recoverer becomes unhealthy after `maxConsecutiveErrors` attempts.
- **Feature flags / rollout:** No flag. The lock is always active when `orphanRecovery.enabled = true`. During a rolling upgrade, old replicas do not take the lock and can scan at the same time as new replicas, which is the same as before this change.

## References

- Prior changelog entry on the aggregator storage: `2026-10-28_aggregator_batch_write_insert.md`
