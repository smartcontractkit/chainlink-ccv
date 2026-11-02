# Indexer discovery runs on one replica at a time (leader lock)

## Executive Summary

- A Postgres advisory lock now selects one indexer replica as the discovery leader. Only the leader reads messages from the aggregators.
- Before this change, each replica read the same aggregator stream, sent all messages to its own worker pool, and could move the discovery cursor back. This is the first step to run more than one indexer replica in one cluster.
- This change affects the indexer only: `indexer/pkg/discovery`, `indexer/pkg/storage`, `indexer/pkg/worker`, `indexer/pkg/config` and `indexer/cmd`.
- It has small breaking changes to Go interfaces and signatures. It adds an optional config table and two metrics.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `common.IndexerMetricLabeler.RecordDiscoveryLeaderGauge`, `IncrementDiscoveryLeaderChanges` | signature-changed | `IndexerMetricLabeler\b` | `indexer/pkg/common/metrics.go:43` | [#indexermetriclabeler-has-new-methods](#indexermetriclabeler-has-new-methods) |
| `worker.Pool.Start` | behavior-changed | `\.Start\(ctx\)` | `indexer/pkg/worker/worker_pool.go:65` | [#pool-start-no-longer-hydrates](#pool-start-no-longer-hydrates) |
| `storage.PostgresStorage.UpdateMessageStatus` | behavior-changed | `\.UpdateMessageStatus\(` | `indexer/pkg/storage/postgres.go:610` | [#timeout-does-not-replace-a-final-status](#timeout-does-not-replace-a-final-status) |
| `indexer.discovery_state.last_sequence_number` | behavior-changed | `discovery_state` | `indexer/pkg/storage/postgres.go:971` | [#discovery-cursor-moves-forward-only](#discovery-cursor-moves-forward-only) |
| `storage.DataSource` | added | `\bstorage\.DataSource\b` | `indexer/pkg/storage/postgres.go:57` | [#discovery-leader-lock](#discovery-leader-lock) |
| `common.DiscoveryLocker`, `common.DiscoveryLease` | added | `DiscoveryLocker\|DiscoveryLease` | `indexer/pkg/common/storage.go:77` | [#discovery-leader-lock](#discovery-leader-lock) |
| `storage.PostgresStorage.TryAcquireDiscoveryLock` | added | `TryAcquireDiscoveryLock\(` | `indexer/pkg/storage/leader_lock.go:24` | [#discovery-leader-lock](#discovery-leader-lock) |
| `discovery.LeaderElector`, `discovery.NewLeaderElector` | added | `NewLeaderElector\(` | `indexer/pkg/discovery/leader.go:40` | [#discovery-leader-lock](#discovery-leader-lock) |
| `discovery.LeadershipGate`, `discovery.WithLeadershipGate` | added | `WithLeadershipGate\(` | `indexer/pkg/discovery/message_discovery.go:165` | [#discovery-leader-lock](#discovery-leader-lock) |
| `worker.Pool.Hydrate` | added | `\.Hydrate\(` | `indexer/pkg/worker/worker_pool.go:77` | [#pool-start-no-longer-hydrates](#pool-start-no-longer-hydrates) |
| `config.Config.LeaderElection` | added | `LeaderElection` | `indexer/pkg/config/config.go:59` | [#discovery-leader-lock](#discovery-leader-lock) |
| `indexer_discovery_leader`, `indexer_discovery_leader_changes` | added | `indexer_discovery_leader` | `indexer/pkg/monitoring/metrics.go:113` | [#metrics](#metrics) |

## Breaking Changes

### IndexerMetricLabeler has new methods

- **What changed:** `common.IndexerMetricLabeler` has two new methods: `RecordDiscoveryLeaderGauge(ctx, isLeader bool)` and `IncrementDiscoveryLeaderChanges(ctx)`.
- **Why:** The elector records which replica is the leader and how often the leadership changes.
- **Who is affected:** All implementations. In this repo they are `monitoring.IndexerMetricLabeler`, `monitoring.NoopIndexerMetricLabeler` and `mocks.MockIndexerMetricLabeler`.

### Pool.Start no longer hydrates

- **What changed:** `worker.Pool.Start`.
- **Before:** `Start` loaded all PROCESSING messages from storage and enqueued them.
- **After:** `Start` only starts the goroutines. The new method `Pool.Hydrate(ctx) error` loads the PROCESSING messages. `cmd/main.go` calls it from `LeaderElector.OnElected`, so only the new leader takes over the retries of the last leader.
- **Who is affected:** Code that builds a `worker.Pool` and expects `Start` to resume the PROCESSING messages. Call `Hydrate` to keep the old behavior.

### TIMEOUT does not replace a final status

- **What changed:** `PostgresStorage.UpdateMessageStatus`.
- **Before:** The UPDATE wrote any status with no condition.
- **After:** Only `SUCCESSFUL` can replace a final status. A `TIMEOUT` changes only a `PROCESSING` message. When the message has a final status and no row changes, the call returns nil. It still returns `message not found` when the message does not exist.
- **Why:** A late `TIMEOUT` from a different task or replica wrote over a `SUCCESSFUL` message.

### Discovery cursor moves forward only

- **What changed:** The cursor update in `PersistDiscoveryBatch` (now `advanceDiscoverySequence`) uses `GREATEST(last_sequence_number, $1)`.
- **Why:** A slow writer, for example an old leader during a leadership change, cannot move the cursor back.

## Migration Guide

1. Add `RecordDiscoveryLeaderGauge` and `IncrementDiscoveryLeaderChanges` to custom `IndexerMetricLabeler` implementations.
2. Regenerate mocks: `just mock`.
3. If you build a `worker.Pool` yourself, call `Hydrate` where the PROCESSING messages must be resumed:

```go
// Before
pool.Start(ctx) // also hydrated
```

```go
// After
pool.Start(ctx)
elector.OnElected(func(ctx context.Context) {
	if err := pool.Hydrate(ctx); err != nil {
		lggr.Errorw("Failed to hydrate", "error", err)
	}
})
elector.Start(ctx)
```

4. No config change is necessary. The `LeaderElection` table is optional.

## New Features / Additions

### Discovery leader lock

- **Lock:** The leader holds `pg_try_advisory_lock(hashtextextended('indexer_discovery', 0))` on a dedicated connection for the full time that it is the leader. It is one lock for all the discovery sources, because the sources work together inside one process (`PrimaryWriteNotifier` and the multi-source dedup).
- **Heartbeat:** The leader runs `SELECT 1` on the lock connection each `HeartbeatInterval`. If a heartbeat fails, the leader cancels its leader context at once and becomes a follower.
- **Stopped leader:** The lock connection sets `idle_session_timeout` to `LeaseTimeout`. If the leader freezes or its pod stops, Postgres closes the session after `LeaseTimeout` and frees the lock.
- **Followers:** They try to get the lock each `AcquireInterval`. A follower does not poll the aggregators.
- **New leader:** On the first poll of each new leadership term, each discovery source loads its cursor again from `indexer.discovery_state`. It does not use an old in-memory cursor. In-flight reads stop when the leadership is lost.
- **Release:** `pg_advisory_unlock` and `RESET idle_session_timeout`, then the connection goes back to the pool. If one of these steps fails, the connection is closed, which also frees the lock.
- **New config table (optional):**

```toml
[LeaderElection]
  LeaseTimeout = "30s"       # default
  HeartbeatInterval = "10s"  # default, must be less than LeaseTimeout
  AcquireInterval = "5s"     # default
```

- **Callers that do not set a gate** (for example the replay CLI) work as before: `WithLeadershipGate` is optional, and with no gate the source always polls.

### Metrics

- Added the gauge `indexer_discovery_leader` (1 = leader, 0 = follower).
- Added the counter `indexer_discovery_leader_changes`.
- No metric was removed or renamed.

## Compatibility & Requirements

- **Postgres:** Version 14 or later, because `idle_session_timeout` is a Postgres 14 setting. On an older version, each lock attempt fails, and no replica becomes the leader.
- **Not in scope:** Only the leader polls the verifiers, so the message processing is not shared across replicas yet. A DB queue for message processing is the next step.
- **Rolling upgrade:** Old replicas do not take the lock and continue to poll. Until all replicas run this version, discovery can run on more than one replica, the same as before this change. The cursor and status guards apply only to the writes of replicas that run the new version.

## References

- Prior changelog entry with the same lock pattern: `2026-10-30_aggregator_orphan_recovery_lock.md`
