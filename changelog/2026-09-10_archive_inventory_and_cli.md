# Archive inventory metrics and archived-job CLI filtering

## Executive Summary

- Operators can see how many failed jobs are still retained, what kind of failure they were, and
  how close they are to the 30-day archive cutoff, from metrics and a Grafana dashboard rather
  than by reading the archive by hand.
- `ccv job-queue list` accepts one or several message IDs and can emit JSON, so an operator (or a
  console shelling out to the CLI) no longer fetches the whole archive and greps a table.
- `ccv job-queue reschedule` infers `--verifier-id` when the selected job has exactly one owner,
  and still refuses to guess when it has more than one.
- **No database migration.** The failure vocabulary is derived from columns the archive tables
  already have, so nothing in this change alters the schema.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `jobqueue.failureCategorySQL` | added | `failureCategorySQL` | `verifier/pkg/jobqueue/archive.go` | [#archive-inventory](#archive-inventory) |
| `jobqueue.PostgresJobQueue.CollectArchiveMetrics` | added | `CollectArchiveMetrics\(` | `verifier/pkg/jobqueue/archive.go` | [#archive-inventory](#archive-inventory) |
| `jobqueue.Store.ListFailedFiltered` | added | `ListFailedFiltered\(` | `cli/jobqueue/store.go` | [#cli-filtering](#cli-filtering) |
| Archive inventory dashboard and alerts | added | `verifier_archive_` | `docs/monitoring/verifier-archive-inventory.md` | [#archive-inventory](#archive-inventory) |

## Breaking Changes

None. No schema change, no new tables or columns, and `job-queue list` keeps its existing
no-filter behavior, both queue types and `--limit 0` semantics.

## Archive inventory

`verifier_archive_failed_jobs`, `verifier_archive_expiring_jobs` and
`verifier_archive_oldest_age_seconds` report retained failed jobs per queue, verifier owner,
source chain and failure category. `verifier_archive_collection_success` and
`verifier_archive_last_success_timestamp` make a failed collection visible, so an empty inventory
is never mistaken for a healthy one. Collection runs once a minute and clears groups that have
disappeared, so a reschedule or cleanup shows up as a transition to zero rather than a stuck value.

The category is derived at read time by `failureCategorySQL` rather than stored. R1 allows either
persisting a category or defining a stable mapping, and every input the mapping needs
(`last_error`, `retry_deadline`, `completed_at`) is already on the archive tables — so the
inventory costs no migration. Retry-window expiry is decided by the timestamps, because a job
archived when its deadline passed carries whatever error last failed it and is otherwise
indistinguishable from that same error elsewhere. The vocabulary is closed: an unmatched error is
`unknown`, never a new label, so metric cardinality is fixed. `TestArchiveFailureCategory` pins
each branch against seeded rows.

No message IDs, job IDs or raw `last_error` text appear in metric labels. The dashboard is
labelled as retained failures rather than distinct replayable messages: duplicate archive rows,
active jobs and messages recovered by another path all mean the count is not a to-do list.

`build/devenv/dashboards/verifier_archive_inventory.json` and
`docs/monitoring/verifier-archive-inventory-alerts.yaml` supply the dashboard, a retention warning
at 23 days (seven days of lead) and a collection-health warning, each linking to the remediation
runbook. The rules are provisioning input; they do not touch a live Grafana. A 100,000-row,
100-owner fixture logs the inventory query's plan, buffers and timing so the collection cost can be
reviewed against a representative archive.

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
