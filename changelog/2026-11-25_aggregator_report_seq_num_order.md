# Aggregator report sequence numbers become visible in order

## Executive Summary

- An aggregated report now gets its `seq_num` only after the previous report commits or rolls back. Readers of `GetMessagesSince` see the reports in `seq_num` order.
- Before this change, two writers could commit in the opposite order of their `seq_num`. A `GetMessagesSince` poll between the two commits moved the client cursor past the lower number. The client then did not receive that report.
- This change affects the aggregator database only: one new migration. No Go interface, config or metric changes.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `next_aggregated_report_seq_num()` | added | `next_aggregated_report_seq_num` | `aggregator/migrations/postgres/00007_serialize_aggregated_report_seq_num.sql` | [#serialized-sequence-allocation](#serialized-sequence-allocation) |
| `commit_aggregated_reports.seq_num` default | behavior-changed | `commit_aggregated_reports_seq_num_seq` | `aggregator/migrations/postgres/00007_serialize_aggregated_report_seq_num.sql` | [#serialized-sequence-allocation](#serialized-sequence-allocation) |

## Breaking Changes

None.

## New Features / Additions

### Serialized sequence allocation

- **New function:** `next_aggregated_report_seq_num()` calls `pg_advisory_xact_lock(5323499729184835101)`, then `nextval('commit_aggregated_reports_seq_num_seq')`. The key is the crc64 ECMA checksum of `aggregated_report_seq_num`. It is different from the migration lock key.
- **New default:** `commit_aggregated_reports.seq_num` uses the new function. The lock holds until the transaction ends. The next writer waits until then.
- **Sequence:** `commit_aggregated_reports_seq_num_seq` keeps `CACHE 1`.
- **Duplicates:** The default runs before the `ON CONFLICT` check. A duplicate submit also takes the lock and uses one number. Gaps in `seq_num` are still possible. Clients must not expect gapless numbers.
- **Unchanged:** `commit_verification_records_seq_num_seq` is not read as a cursor and keeps `nextval()`.

## Compatibility & Requirements

- **Rolling deploy:** Old and new binaries use the column default. After the migration, all replicas use the serialized allocation. No binary change is necessary.
- **Migration lock:** `ALTER COLUMN ... SET DEFAULT` needs an exclusive lock on `commit_aggregated_reports` for a short time. The migration sets `lock_timeout = 5s`. If the timeout occurs, the migration fails and the aggregator does not start. The next start tries the migration again.
- **Write throughput:** Report inserts now run one at a time per database. Each insert is one short statement. With synchronous replication, the lock also holds while the standby confirms the commit.
- **Rollback:** The Down migration sets the default back to `nextval('commit_aggregated_reports_seq_num_seq')` and drops the function.

## References

- Prior changelog entry on the aggregator storage: `2026-10-30_aggregator_orphan_recovery_lock.md`
