# Archived-job CLI filtering and read-time failure classification

## Executive Summary

- `ccv job-queue list` accepts one or several message IDs and can emit JSON, so an operator (or a
  console shelling out to the CLI) no longer fetches the whole archive and greps a table.
- `ccv job-queue reschedule` infers `--verifier-id` when the selected job has exactly one owner,
  and still refuses to guess when it has more than one.
- Failed rows carry a bounded read-time failure category (policy rejection, retry expiry, known
  validation/deserialization failure, storage failure, unknown), derived from columns the archive
  tables already have.
- **No database migration.** Nothing in this change alters the schema.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `archivecategory.SQL` | added | `archivecategory\.SQL` | `verifier/pkg/jobqueue/archivecategory/category.go` | [#cli-filtering](#cli-filtering) |
| `jobqueue.Store.ListFailedFiltered` | added | `ListFailedFiltered\(` | `cli/jobqueue/store.go` | [#cli-filtering](#cli-filtering) |

## Breaking Changes

None. No schema change, no new tables or columns, and `job-queue list` keeps its existing
no-filter behavior, both queue types and `--limit 0` semantics.

## Failure classification

The category is derived at read time by `archivecategory.SQL` rather than stored. Every input the
mapping needs (`last_error`, `retry_deadline`, `completed_at`) is already on the archive tables —
so classification costs no migration. Retry-window expiry is decided by the timestamps, because a
job archived when its deadline passed carries whatever error last failed it and is otherwise
indistinguishable from that same error elsewhere. The vocabulary is closed: an unmatched error is
`unknown`, never a new label. `TestArchiveFailureCategory` pins each branch against seeded rows.

## CLI filtering

`job-queue list` takes `--message-id` with comma-separated or repeated values. IDs are normalized
for hex prefix and case, deduplicated, and malformed input is rejected with the offending value.
The filter is applied in the database before ordering and `--limit`, alongside any queue and owner
filters, so an older matching row is not hidden behind the default 50 newest per queue.

`--json` emits queue, job ID, full message ID, owner, source selector, attempts, full last error
and the archive/retry timestamps. Diagnostics stay on stderr so the stdout stream stays parseable,
and chain selectors are strings so a browser client cannot lose precision on them.

## Owner inference

`job-queue reschedule` resolves the owner from matching failed archive rows in the selected queue.
Exactly one match reschedules for that owner and names it in the result. Zero matches is an error
that changes nothing. More than one returns the candidate owner IDs and requires `--verifier-id`;
it never fans out. An explicit owner is always honored and never falls back to a different one.
Several matching rows for one owner remain the existing `--job-id` ambiguity, and the atomic
archive restore and active-job uniqueness checks are unchanged.

## Scope

This is R1–R3 of the recovery follow-ups. R4 (durable pre-admission drop history) and R5 (live
source-range recovery) are not included; both need durable storage and are being taken separately
so the schema question can be argued on its own terms.
