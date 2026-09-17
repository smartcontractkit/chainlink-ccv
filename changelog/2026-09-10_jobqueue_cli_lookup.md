# Archived-job lookup by message ID, JSON output, and owner inference

## Executive Summary

- `ccv job-queue list` accepts one or several message IDs and can emit JSON, so an operator no
  longer fetches the whole archive and greps a table.
- `ccv job-queue reschedule` infers `--verifier-id` when the selected job has exactly one owner,
  and still refuses to guess when it has more than one.
- No database migration and no new metrics.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `jobqueue.Store.ListFailedFiltered` | added | `ListFailedFiltered\(` | `cli/jobqueue/store.go` | [#cli-filtering](#cli-filtering) |
| `jobqueue.ParseMessageIDs` | added | `ParseMessageIDs\(` | `cli/jobqueue/commands.go` | [#cli-filtering](#cli-filtering) |

## Breaking Changes

`jobqueue.Store` gains `ListFailedFiltered`; an implementation outside this repo must add it. The
generated mock is updated. `job-queue list` keeps its existing no-filter behavior, both queue
types and `--limit 0` semantics.

## CLI filtering

Implements [CCIP-13499](https://smartcontract-it.atlassian.net/browse/CCIP-13499).

`job-queue list` takes `--message-id` with comma-separated or repeated values. IDs are normalized
for hex prefix and case, deduplicated, and malformed input is rejected with the offending value.
The filter is applied in the database before ordering and `--limit`, alongside any queue and owner
filters, so an older matching row is not hidden behind the default 50 newest per queue.

`--json` emits queue, job ID, full message ID, owner, source selector, attempts, full last error
and the archive/retry timestamps. Diagnostics stay on stderr so the stdout stream stays parseable,
and chain selectors are strings so a browser client cannot lose precision on them.

## Owner inference

Implements [CCIP-13500](https://smartcontract-it.atlassian.net/browse/CCIP-13500).

`job-queue reschedule` resolves the owner from matching failed archive rows in the selected queue.
Exactly one match reschedules for that owner and names it in the result. Zero matches is an error
that changes nothing. More than one returns the candidate owner IDs and requires `--verifier-id`;
it never fans out. An explicit owner is always honored and never falls back to a different one.
Several matching rows for one owner remain the existing `--job-id` ambiguity, and the atomic
archive restore and active-job uniqueness checks are unchanged.

## Deferred

Archive inventory metrics ([CCIP-13475](https://smartcontract-it.atlassian.net/browse/CCIP-13475))
were dropped from this change. The collection query added a recurring per-minute read against the
archive tables, and the verifier already has per-queue metric queries that are among the larger
contributors to database load, so the right shape for this class of metric is an open question:
added indexes, a materialized view, or pushing aggregation into the database on a slower cadence.
That is being decided on the ticket rather than settled here.

Durable pre-admission drop history
([CCIP-13501](https://smartcontract-it.atlassian.net/browse/CCIP-13501)) and live source-range
recovery ([CCIP-13502](https://smartcontract-it.atlassian.net/browse/CCIP-13502)) are likewise
separate.
