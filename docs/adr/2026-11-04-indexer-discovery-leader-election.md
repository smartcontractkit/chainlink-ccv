# ADR: Leader election for CCV indexer message discovery

**Authors**: @carte7000

**PR**: [#1567](https://github.com/smartcontractkit/chainlink-ccv/pull/1567)

## Problem statement

We want to run more than one indexer replica in each region. The indexer gets new messages from a stream that the aggregator supplies (`GetMessagesSince`, with a sequence-number cursor). Each replica that reads this stream gets all the messages.

With N replicas, the aggregator gets N times the read load, and each replica sends all the messages to its own workers. The workers then poll the verifiers N times for each message. This work has no value, because all the replicas in a region write the results to the same database.

## Goals

- Only one replica in a region reads the aggregator stream at a time.
- When this replica stops, freezes or loses its database connection, a different replica continues from the cursor in the database, with no manual action.
- The other replicas continue to serve the indexer API from the shared database.
- The change is safe during a rollout and can be turned off with a config flag.

### Anti-Goals

- Distribute the message processing (the verifier polling) across the replicas. A work queue does this in a later change (see "Context").
- Increase the discovery throughput. One reader is sufficient for the stream.
- Coordinate replicas across regions. Each region has its own database and its own leader.

## Context

- **The stream:** The aggregator gives one ordered stream of messages for each discovery source. The stream has one cursor (a sequence number). The aggregator does not partition the stream, so a reader cannot ask for only a part of the messages.
- **The database:** All the indexer replicas in a region use the same Postgres database. The discovery cursor (`indexer.discovery_state`), the messages and the verifier results are in this database.
- **Discovery in one process:** With more than one discovery source, the sources work together inside one process: a primary source signals its writes (`PrimaryWriteNotifier`), and a merge step removes duplicate messages across the sources. So all the sources must run in the same replica.
- **The next step:** We will add a database queue between discovery and the workers. Discovery will write each message to the queue. The workers on all the replicas will take messages from the queue to poll the verifiers. This distributes the processing evenly across the replicas, and a message that a stopped replica did not complete goes back to the queue. After this change, the workers no longer need to load the PROCESSING messages from storage when a replica starts.
- **Same pattern:** The aggregator orphan recovery already uses a Postgres advisory lock so that one replica at a time does the scan (#1563).

## Decisions

1. **One discovery leader in each region, selected with a Postgres session advisory lock.**
   - The leader holds `pg_try_advisory_lock(hashtextextended('indexer_discovery', 0))` on a dedicated connection for the full time that it is the leader.
   - One lock covers all the discovery sources, because the sources work together inside one process.
   - The lock code is in the shared package `common/pgadvisorylock`. The aggregator uses the same package.
2. **A lease, with a heartbeat, frees the lock when the leader stops.**
   - The lock connection sets `idle_session_timeout` to `LeaseTimeout` (default 30s). If the leader freezes or its pod stops, Postgres closes the session and frees the lock.
   - The leader sends `SELECT 1` on the lock connection each `HeartbeatInterval` (default 10s). If a heartbeat fails, the leader stops discovery at once.
   - The followers try to get the lock each `AcquireInterval` (default 5s).
3. **A new leader starts from the database.** It loads the cursor of each source from `indexer.discovery_state` before its first read. It never uses an old cursor from its memory.
4. **Guards for the short time when two leaders can run.**
   - The cursor update uses `GREATEST`, so the cursor cannot move back.
   - A `TIMEOUT` status cannot replace a final status.
   - The message and result writes are idempotent.
5. **A config flag, off by default.** `[LeaderElection] Enabled` turns the lock on. When it is off, the indexer works as before. Devenv turns it on.

## Implications

- **Aggregator load:** The read load on the aggregator does not change with the number of indexer replicas.
- **Processing:** Until the queue is added, only the leader polls the verifiers. The followers serve only the API. The processing capacity of a region is the capacity of one replica.
- **Failover time:** When the leader stops, discovery stops for up to `LeaseTimeout + AcquireInterval` (about 35s with the defaults). No message is lost, because the new leader starts from the cursor in the database.
- **Database:**
  - The leader keeps one connection for the lock, so the pool must have at least 2 connections. Config validation checks this.
  - The `idle_session_timeout` setting needs Postgres 14 or later.
- **Liveness, not progress:** The lock shows that the leader process and its database connection are alive. It does not show that discovery makes progress. A leader with stuck workers keeps the lock. The queue reduces this risk, because the workers on all replicas take the work.
- **Replay:** The replay CLI runs as a separate job outside the service. It does not take the lock, so the number of replicas has no effect on it.
- **Observability:**
  - New metrics: `indexer_discovery_leader` (1 on the leader), `indexer_discovery_leader_changes` and `indexer_discovery_leader_errors`.
  - The elector is a health reporter: a follower is healthy, and repeated lock errors make it not ready.

## Alternatives considered

### Each replica reads the full stream (no coordination)

All the replicas read the stream and write to the shared database. The writes are idempotent.

#### Pros

- No new code and no coordination.
- No failover delay.

#### Cons

- The aggregator read load increases with each replica.
- Each replica polls the verifiers for each message, so the verifier load also increases with each replica.
- A slow replica can move the shared cursor back, unless the cursor update has a guard.

### Shard the stream by message ID

Each replica reads only the messages for which `hash(messageID) mod N` is its own index.

#### Pros

- The read work is distributed across the replicas.
- No leader and no failover delay for the full stream.

#### Cons

- The aggregator does not partition the stream. Each replica must still read the full stream and drop the messages of the other shards, so the aggregator load does not decrease.
- The stream has one cursor. One cursor for each shard needs changes in the aggregator API and in the indexer schema.
- All the replicas in a region share one database, so the sharding adds no storage benefit.
- A change in the number of replicas needs a rebalance of the shards.

### Leader election with a lease table

The leader holds a row in a lease table, and renews `expires_at` at an interval (the same as `common/dblease`, which the node uses).

#### Pros

- Does not need a dedicated connection for the full leadership.
- Works on Postgres versions before 14.

#### Cons

- Needs a new table and a migration.
- Correct behavior depends on the clocks and on the renew timing. With an advisory lock, Postgres frees the lock when the session closes.
- `common/dblease` stops the process with `Fatal` when it loses the lease. That is not correct for the indexer, which must continue to serve the API as a follower.

## Alternatives not considered

**A message bus with consumer groups (for example Kafka)**
The aggregator gives a gRPC stream, not a topic on a message bus. A bus would need a new component in each region and a change to the aggregator. This is too large for the problem. We can look at this again if the aggregator publishes to a bus in the future.
