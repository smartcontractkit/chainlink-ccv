# Generic dedup key for the job queue

## Executive Summary

- `common/jobqueue` identifies a job by a generic string key, `Jobable.DedupKey()`, in place of the fixed `(chain_selector, message_id)` pair.
- This lets services other than the verifier (aggregator, indexer) use the queue with their own keys.
- Affects every `jobqueue.Jobable` implementation, readers of `jobqueue.Job[T].ChainSelector` / `.MessageID`, the verifier PostgreSQL schema (migration `00010`) and the standalone verifier wiring.
- Breaking for Go consumers: `Jobable` gets a new method, two `Job` fields are removed, and the zero value of `QueueConfig.KeyColumns` selects the new `dedup_key` column. The Chainlink-node verifier keeps its current schema and behavior.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `jobqueue.Job.ChainSelector`, `jobqueue.Job.MessageID` | removed | `\.(ChainSelector\|MessageID)\b` on `jobqueue.Job` values | — | [#job-fields-removed](#job-fields-removed) |
| `jobqueue.Jobable` | signature-changed | `jobqueue\.Jobable\b\|\) JobKey\(\)` | `common/jobqueue/interface.go:20` | [#jobable-needs-dedupkey](#jobable-needs-dedupkey) |
| `jobqueue.QueueConfig.KeyColumns` zero value | behavior-changed | `jobqueue\.NewPostgresJobQueue\[` | `common/jobqueue/interface.go:137` | [#keycolumns-default](#keycolumns-default) |
| `jobqueue.MessageKeyed` | added | `\bMessageKeyed\b` | `common/jobqueue/interface.go:27` | [#jobable-needs-dedupkey](#jobable-needs-dedupkey) |
| `jobqueue.MessageDedupKey` | added | `MessageDedupKey\(` | `common/jobqueue/interface.go:35` | [#dedup-key-format](#dedup-key-format) |
| `jobqueue.KeyColumns`, `DedupKeyColumn`, `MessageKeyColumns` | added | `jobqueue\.(KeyColumns\|DedupKeyColumn\|MessageKeyColumns)\b` | `common/jobqueue/interface.go:40` | [#keycolumns-default](#keycolumns-default) |
| `jobqueue.Job.DedupKey` | added | `\.DedupKey\b` | `common/jobqueue/interface.go:52` | [#job-fields-removed](#job-fields-removed) |
| `jobqueue.CreateTablesSQL` | added | `CreateTablesSQL\(` | `common/jobqueue/schema.go:7` | [#new-queue-tables](#new-queue-tables) |
| `verifier.WithDedupKeyColumn` | added | `verifier\.NewCoordinator(WithDetector)?\(` | `verifier/pkg/coordinator.go:97` | [#verifier-wiring](#verifier-wiring) |
| `protocol.VerifierNodeResult.DedupKey`, `vtypes.VerificationTask.DedupKey` | added | `DedupKey\(\)` | `protocol/message_types.go:591`, `verifier/pkg/vtypes/types.go:37` | [#dedup-key-format](#dedup-key-format) |
| `ccv_task_verifier_jobs`, `ccv_storage_writer_jobs` (+ `_archive`) schema | behavior-changed | `ccv_(task_verifier\|storage_writer)_jobs` | `verifier/migrations/postgres/00010_job_queue_dedup_key.sql:1` | [#schema-and-rollback](#schema-and-rollback) |

## Breaking Changes

<a id="jobable-needs-dedupkey"></a>
### `Jobable` needs `DedupKey()`

- **What changed:** `jobqueue.Jobable`.
- **Before:** `JobKey() (chainSelector uint64, messageID []byte)`.
- **After:** `DedupKey() string`. `JobKey()` moved to the new optional interface `jobqueue.MessageKeyed`.
- **Why:** the key must not depend on a chain selector and a message ID, so that other services can use the queue.
- **Who is affected:** every payload type passed to `NewPostgresJobQueue`. Types that only have `JobKey()` no longer compile.

`MessageKeyed` is write-only. A payload that implements it also writes the legacy `chain_selector` and `message_id` columns on insert. The queue never reads these columns back. Only payloads stored in the verifier tables must implement it.

<a id="job-fields-removed"></a>
### `Job.ChainSelector` and `Job.MessageID` removed

- **What changed:** `jobqueue.Job[T]`.
- **Before:** consume set `ChainSelector` and `MessageID` from the table columns.
- **After:** both fields are removed. The new field `Job.DedupKey` holds the key. Read message data from `Job.Payload`.
- **Why:** no production code read these fields, and the queue no longer parses key columns.
- **Who is affected:** code that reads these fields from consumed jobs.

<a id="keycolumns-default"></a>
### `QueueConfig.KeyColumns` and its zero value

- **What changed:** new field `QueueConfig.KeyColumns`. Its zero value is `DedupKeyColumn`.

| Mode | Unique key | Consume returns | Use |
|---|---|---|---|
| `DedupKeyColumn` (zero value) | `(owner_id, dedup_key)` | `dedup_key` | new tables, standalone verifier |
| `MessageKeyColumns` | `(owner_id, chain_selector, message_id)` | no key column; `Job.DedupKey` comes from the payload | verifier tables on a Chainlink node |

- With `MessageKeyColumns`, `DedupKey()` has no effect on duplicates.
- `NewPostgresJobQueue` returns an error for `MessageKeyColumns` when T does not implement `MessageKeyed`.
- **Who is affected:** code that calls `NewPostgresJobQueue` directly with a table that has no `dedup_key` column. Before this change, that table worked without the field. Now it needs `KeyColumns: jobqueue.MessageKeyColumns`, or the first statement fails.

## Migration Guide

1. Add `DedupKey() string` to every `jobqueue.Jobable` payload. For a payload stored in the verifier tables, keep `JobKey()` and return the message key:

```go
// Before
func (p Payload) JobKey() (uint64, []byte) { return p.Chain, p.MessageID }
```

```go
// After
func (p Payload) JobKey() (uint64, []byte) { return p.Chain, p.MessageID }
func (p Payload) DedupKey() string        { return jobqueue.MessageDedupKey(p.JobKey()) }
```

2. Replace reads of `job.ChainSelector` / `job.MessageID` with fields of `job.Payload`.
3. For a direct `NewPostgresJobQueue` call on a table without `dedup_key`, set `KeyColumns: jobqueue.MessageKeyColumns`.
4. The Chainlink node embeds the verifier through `integration/pkg/constructors`. It needs no change: the coordinator selects `MessageKeyColumns` when no option is given.

## New Features / Additions

<a id="dedup-key-format"></a>
- **`jobqueue.MessageDedupKey(chainSelector, messageID)`** returns `<hex message id>:<chain selector>`, for example `aa01:1`. The message ID comes first, so a lookup by message ID alone is a prefix match. `VerificationTask.DedupKey()` and `VerifierNodeResult.DedupKey()` return this format. The verifier tables keep their `(chain_selector, message_id)` constraint, so payloads stored there must use this format. Another key causes a unique-constraint error on publish.

<a id="new-queue-tables"></a>
- **`jobqueue.CreateTablesSQL(name)`** returns the DDL for a `DedupKeyColumn` queue table and its archive. These tables have `dedup_key` and no legacy columns. Copy the output into the service's goose migration. Payloads for these tables must not implement `MessageKeyed`, because the insert would name columns that do not exist.

<a id="verifier-wiring"></a>
- **`verifier.WithDedupKeyColumn()`** is a coordinator option that makes both verifier queues use `DedupKeyColumn`. The standalone binaries in `cmd/verifier` pass it next to `WithSourceRecovery()`. Without it, the coordinator uses `MessageKeyColumns`. This is the Chainlink-node path, and `TestCoordinatorQueueKeys` covers the default.

## Compatibility & Requirements

<a id="schema-and-rollback"></a>
### Schema and rollback

Migration `00010_job_queue_dedup_key.sql` (standalone verifier only) does the following:

- adds `dedup_key` to `ccv_task_verifier_jobs` and `ccv_storage_writer_jobs`, fills it for existing rows, sets it NOT NULL and adds `UNIQUE (owner_id, dedup_key)`;
- keeps the `chain_selector` and `message_id` columns and the `(owner_id, chain_selector, message_id)` constraint;
- adds a `BEFORE INSERT` trigger that fills `dedup_key` when an insert does not set it, on the active and archive tables;
- adds a nullable `dedup_key` to the archive tables. It does not fill archive rows from before the migration.

Results:

- A verifier from before this change runs on the migrated schema. Its inserts get `dedup_key` from the trigger, and the new code reads its rows. A code rollback therefore needs no down migration.
- The new code writes the legacy columns for verifier payloads, so the old code and the `ccv job-queue` CLI read new rows.
- The down migration removes the trigger, the function and the `dedup_key` columns.
- A Chainlink node applies its own copies of the queue migrations and does not get `00010`. It runs `MessageKeyColumns` on its existing schema.

A later change will drop the legacy columns and the old constraint from the standalone tables, and will move the CLI to `dedup_key` lookups. That change waits until a rollback to code from before this change is no longer needed.

### Validation

- `common/jobqueue/compat_test.go` runs SQL copied from the queue before this change next to the new code. It covers both key modes on the migrated schema and `MessageKeyColumns` on the schema without `dedup_key`, for both verifier tables.
- It also covers goose down and up while jobs are in the tables, and that the trigger key equals `MessageDedupKey`.
- The EXPLAIN goldens in `common/jobqueue/testdata` now show the `dedup_key` conflict index and the trigger calls. The scan types did not change.

## References

- Builds on: `2026-08-31_queue_signal_driven_wakeup.md`, `2026-09-11_source_recovery.md`.
- The package move from `verifier/pkg/jobqueue` to `common/jobqueue` landed earlier, in #1487.
