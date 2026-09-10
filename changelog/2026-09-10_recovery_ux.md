# Durable verifier recovery and replay UX (R1–R5)

## Executive Summary

- Adds archive inventory/expiry monitoring, exact multi-ID lookup, owner inference, durable drop evidence and bounded live source recovery.
- Operators can recover retained jobs or canonical source ranges without restarting the standalone verifier, including an explicit investigated reset of a disabled reader.
- Affects verifier PostgreSQL schema, source-reader/queue coordination, the standalone CLI and devenv coverage. Admin UI and Chainlink core command wiring are outside this change.
- Adds methods to the CLI store interface and optional reader metadata; consumers implementing that interface must adapt. No chain-family dependency is added to recovery or policy.

## AI Adapter Index

Read each matching row's section when adapting a downstream consumer. Unlisted symbols keep their existing contracts.

| Symbol | Kind | Search | Location | Section |
| --- | --- | --- | --- | --- |
| `cli/jobqueue.Store` | signature-changed | `jobqueue\.Store\b` | `cli/jobqueue/store.go:48` | [#archive-cli](#archive-cli) |
| `ccv job-queue list message filters / JSON` | behavior-changed | `job-queue list` | `cli/jobqueue/commands.go:98` | [#archive-cli](#archive-cli) |
| `ccv job-queue reschedule owner selection` | behavior-changed | `job-queue reschedule` | `cli/jobqueue/commands.go:140` | [#archive-cli](#archive-cli) |
| `jobqueue.PostgresStore.ListFailed` | behavior-changed | `\.ListFailed\(` | `cli/jobqueue/postgres_store.go:42` | [#archive-cli](#archive-cli) |
| `jobqueue.PostgresStore.RescheduleByJobID / RescheduleByMessageID` | behavior-changed | `\.RescheduleBy(JobID|MessageID)\(` | `cli/jobqueue/postgres_store.go:171` | [#archive-cli](#archive-cli) |
| `jobqueue.PostgresJobQueue.Fail / Retry` | behavior-changed | `\.Fail\(|\.Retry\(` | `verifier/pkg/jobqueue/postgres_queue.go:545` | [#archive-inventory](#archive-inventory) |
| `jobqueue.ObservabilityDecorator` | behavior-changed | `NewObservabilityDecorator` | `verifier/pkg/jobqueue/observability_decorator.go:111` | [#archive-inventory](#archive-inventory) |
| `verifier.NewCoordinatorWithDetector disabled-reader startup` | behavior-changed | `NewCoordinator(WithDetector)?\(` | `verifier/pkg/coordinator.go:92` | [#live-source-recovery](#live-source-recovery) |
| `sourcereader.Service admission and finality audit` | behavior-changed | `sourcereader\.NewService` | `verifier/pkg/sourcereader/service.go:647` | [#drop-and-incident-history](#drop-and-incident-history) |
| `sourcereader.FinalityViolationCheckerService.UpdateFinalized` | behavior-changed | `\.UpdateFinalized\(` | `verifier/pkg/sourcereader/finality_checker.go:86` | [#live-source-recovery](#live-source-recovery) |
| `ccv_task_verifier_jobs_archive / ccv_storage_writer_jobs_archive schema` | behavior-changed | `ccv_(task_verifier|storage_writer)_jobs_archive` | `verifier/migrations/postgres/00009_recovery.sql:1` | [#schema-and-rollout](#schema-and-rollout) |
| `protocol.MessageSentEvent.BlockHash` | added | `MessageSentEvent\s*\{` | `protocol/common_types.go:357` | [#reader-metadata](#reader-metadata) |
| `vtypes.VerificationTask.SourceBlockHash` | added | `VerificationTask\s*\{` | `verifier/pkg/vtypes/types.go:17` | [#reader-metadata](#reader-metadata) |
| `jobqueue.ArchivedJob.FailureCategory` | added | `ArchivedJob\b` | `cli/jobqueue/store.go:44` | [#archive-inventory](#archive-inventory) |
| `jobqueue.ParseMessageIDs` | added | `ParseMessageID` | `cli/jobqueue/commands.go:240` | [#archive-cli](#archive-cli) |
| `jobqueue.PostgresStore.ListFailedFiltered / Reschedule` | added | `NewPostgresStore` | `cli/jobqueue/postgres_store.go:47` | [#archive-cli](#archive-cli) |
| `jobqueue.FailureCategory / CollectArchiveMetrics` | added | `NewPostgresJobQueue` | `verifier/pkg/jobqueue/archive.go:24` | [#archive-inventory](#archive-inventory) |
| `jobqueue.PostgresJobQueue.PublishInTransaction / NotifyPublished` | added | `NewPostgresJobQueue` | `verifier/pkg/jobqueue/postgres_queue.go:106` | [#live-source-recovery](#live-source-recovery) |
| `recovery.Store operations, history and metrics` | added | `ccv recovery|recovery\.NewStore` | `verifier/pkg/recovery/store.go:16` | [#live-source-recovery](#live-source-recovery) |
| `ccv recovery CLI / recovery.InitCommandsWithFactory` | added | `RunCCVCLI|Subcommands` | `cli/recovery/commands.go:28` | [#live-source-recovery](#live-source-recovery) |
| `sourcereader.Service.ConfigureRecovery` | added | `sourcereader\.NewService` | `verifier/pkg/sourcereader/recovery.go:46` | [#live-source-recovery](#live-source-recovery) |
| `chainstatus.Batcher.ApplyRecoveryReset` | added | `NewChainStatusBatcher` | `verifier/pkg/chainstatus/batcher.go:291` | [#live-source-recovery](#live-source-recovery) |
| `sourcereader.FinalityEvidence / Evidence` | added | `FinalityViolationCheckerService` | `verifier/pkg/sourcereader/finality_checker.go:311` | [#drop-and-incident-history](#drop-and-incident-history) |
| `ccv_recovery_readers / events / operations` | added | `ccv_chain_statuses` | `verifier/migrations/postgres/00010_source_recovery.sql:1` | [#schema-and-rollout](#schema-and-rollout) |
| `verifiercli.Client recovery and JSON helpers` | added | `verifiercli\.NewClient` | `build/devenv/tests/e2e/verifiercli/recovery.go:16` | [#validation](#validation) |
| `Verifier Recovery dashboard and alert provisioning` | added | `verifier_archive_|verifier_recovery_` | `docs/monitoring/verifier-recovery.md:1` | [#archive-inventory](#archive-inventory) |

## Breaking Changes

### CLI store implementations

`cli/jobqueue.Store` previously required `ListFailed`, `RescheduleByJobID` and `RescheduleByMessageID`. It now also requires:

```go
ListFailedFiltered(ctx context.Context, queues []QueueType, ownerID string, messageIDs [][]byte, limit int) ([]ArchivedJob, error)
Reschedule(ctx context.Context, queue QueueType, ownerID, jobID string, messageID []byte, retryDuration time.Duration) (ArchivedJob, error)
```

Implementations and mocks must support exact filtering before limiting and transactional owner resolution. Existing three method signatures remain. Adding exported fields to `MessageSentEvent`, `VerificationTask` and `ArchivedJob` also requires adapting any downstream unkeyed struct literals; prefer keyed literals.

## Migration Guide

1. Upgrade the database through the existing verifier migration mechanism to include 00009 and 00010 before using new code. Both Up and Down definitions are included.
2. Add the two CLI store methods to custom implementations/mocks, retaining the old signatures. The checked-in mock has been updated manually because Go generation was prohibited during this task.
3. Preserve optional block hashes from your reader when available. Omission remains supported and is represented as absent evidence; do not derive chain-specific values in policy or recovery.
4. Standalone command wiring is included in `cmd/verifier/run_ccv_cli.go`. A downstream Chainlink core CLI must add the command group itself. The backend is configured by the shared coordinator.
5. Import the dashboard and provision alert rules through your deployment's Grafana workflow. The files use datasource UID `victoriametrics`; adjust organization/routing for your installation.

## Archive CLI

R2: `job-queue list --message-id` accepts repeated or comma-separated full 32-byte hex IDs, normalizes prefix/case, deduplicates and rejects malformed/empty entries. Queries filter owner/message/queue before ordering and limiting. Existing no-filter behavior and `--limit 0` remain; the default is 50 rows per queue. `--output json` returns an array with full IDs/errors, archive/retry times, attempts/category and decimal-string source selectors. CLI logger output now goes to stderr.

R3: omitted `--verifier-id` on reschedule succeeds only for exactly one matching failed archive owner/job in the selected queue. No match errors; multiple owners list the candidates; multiple jobs for one owner/message require `--job-id`. Explicit owners never fall back. Row selection, archive deletion and active insertion share a transaction. The existing active unique key prevents concurrent duplicate restoration, and conflicts preserve the archive.

A task-verifier restore repeats normal verification/policy on the saved payload. A storage-writer restore repeats only persistence. Neither reruns source admission. See `cli/jobqueue/README.md` for flags and examples.

## Archive Inventory

R1: migration 00009 adds bounded persisted `failure_category` values to both archives and partial indexes for failed-inventory aggregation and message lookup. New archival classification distinguishes policy rejection, retry expiry, known validation/deserialization failure, storage failure and unknown. Pre-upgrade rows retain unknown; classification is advisory and does not change retry/policy decisions.

Both queue observers collect retained failed inventory at startup and every minute, separately from ten-second active queue-size collection. The query has a two-second timeout and avoids JSON/error-text decoding. Metrics expose failed count, count within seven days of the unchanged 30-day retention cutoff, oldest archive age, collection success and last successful timestamp. Removed groups emit zero after successful collection; query failure leaves last-good inventory and exposes stale/failed collection. Empty startup groups have no series until observed; use collection health to interpret absence. No message IDs or raw errors are labels.

`build/devenv/dashboards/verifier_recovery.json` and `docs/monitoring/verifier-recovery-alerts.yaml` provide the dashboard, retention warning, collection-health warning and audit-failure warning with remediation links. Rules are supplied for provisioning, not installed into a live Grafana. A 100,000-row/100-owner PostgreSQL fixture records the inventory execution plan, timing and buffers when run. No runtime or production latency measurement was performed in this task.

## Drop and Incident History

R4: `ccv_recovery_events` stores confirmed reader admission drops separately from job archives. Records include owner/node, known message/lane/source block, bounded stage/reason, observation times/count and optional reader-provided transaction/block hashes. Finality detection records a separate incident with conflicting-header evidence, pending and sent-tracking flush counts, and links known pending messages. Published jobs and attestations are not deleted.

`ccv recovery events` offers owner/source/destination/reason/ID/time/block filters before keyset pagination, with decimal-string cursors and explicit history/reader coverage metadata. Deduplication includes owner/node/source/message/block/hash/transaction/reason/incident. Reobservation extends the 30-day evidence retention window. Bounded hourly cleanup excludes expired evidence from queries even when a deletion backlog remains.

Unknown admission state is waiting, not a drop. The rules checker returns only a boolean, so it cannot supply a rule ID. Disabled intervals, downtime, pre-upgrade traffic, failed audit writes and expired evidence require canonical source investigation. Audit failure is logged/metered and its count persists at the next successful heartbeat; a crash before heartbeat can lose that count. Audit failure cannot prevent the reader's finality block.

## Live Source Recovery

R5: `ccv recovery replay` submits an explicit owner/source and inclusive range, actor/note and optional UUID idempotency key. An omitted target captures the reader's advertised head at submission if its observation is less than one minute old. The fixed target is returned in durable JSON; it never follows later heads. List/status/cancel/resume expose progress and admission/drop/conflict/filter/error counts.

The reader reuses normal event filtering, message-ID validation, curse/rules and finality admission, then publishes ordinary verification tasks. Normal replay leaves normal checkpoints intact. One chunk per owner runs at a time in the process, with database serialization per owner/source. Chunks are capped by configured MaxBlockRange and 100 blocks, 1,000 returned events, source poll timeout and 10,000 active verification jobs per owner. Queue writes, evidence and progress commit together. Cancellation waits for an in-flight chunk, and abrupt failure resumes from the last committed cursor. Active uniqueness prevents duplicate active jobs; completed/attested messages can be verified again and archives are not reconciled.

`reset-reader` is a separate investigated operation requiring a disabled reader, including one disabled at startup. It seeds a fresh checker at `from-block - 1` (zero for genesis), coordinates durable boundary/enabled state and operator audit with checkpoint-buffer reset, and reserves normal polling until the range completes. Cancel/failure leaves that reservation durable across restart; resume finishes it. A later finality violation remains sticky and needs a new investigated reset. Completion refuses to advance a newly disabled database row and persists no checkpoint beyond current finality. Block zero now counts as initialized checker history rather than an initialization sentinel.

`chainstatus.Batcher.ApplyRecoveryReset` requires the caller to serialize reader polling and supply an atomic persistence callback. `PostgresJobQueue.PublishInTransaction` requires an existing caller-owned transaction and must be followed by `NotifyPublished` only after commit. `Service.ConfigureRecovery` is called before Start and requires a synchronized checkpoint manager; coordinator wiring provides it.

Normal polling retains its existing single-owner deployment contract. The new advisory lock protects recovery requests, not arbitrary concurrent normal readers sharing one owner/source. See `cli/recovery/README.md` and `docs/runbooks/remediating-stuck-or-dropped-messages.md`; the runbook retains the legacy stop/set/start fallback and distinguishes verifier replay from indexer backfill.

## Reader Metadata

`protocol.MessageSentEvent.BlockHash` and `vtypes.VerificationTask.SourceBlockHash` carry optional opaque bytes supplied by chain readers. The EVM adapter copies the hash it already received with the log; it adds no RPC and no EVM logic outside the reader. The task field uses `omitempty` for old payload compatibility. Recovery accepts absent metadata and uses no EVM address padding, transaction-origin extraction or chain-family assumptions.

## Schema and Rollout

Migration 00009 adds archive categories plus inventory/message indexes. Migration 00010 adds reader registration/coverage, drop/incident/reset evidence and durable recovery operations with owner/source linkage and pending/retention indexes. Existing automatic retry and archive cleanup durations are unchanged. Event evidence and terminal operation history have separate 30-day cleanup; active/blocked requests and an applied reset retaining polling ownership are not deleted.

There is no dependency bump, protocol message encoding change, new policy bypass, admin UI or external publication in this change. Operation IDs are local to the member database; cross-node fan-out remains outside the verifier.

## Validation

Added CLI tests for multi-ID/JSON/owner behavior and recovery argument/precision handling; PostgreSQL tests for filtered queries, ambiguity, active conflict, concurrent restore, inventory lifecycle/cost, evidence dedup/pagination/retention, transactional rollback, cancellation and restart state; reader tests for shared admission, metadata, unknown-state waits, overlapping pending/drop reconciliation, RPC failures, chunk bounds, live disabled-reader reset, later sticky violations and audit failure; checkpoint-batcher and finality-header evidence tests including genesis.

Devenv scenarios cover policy rejection and live replay, inferred-owner reschedule, curse/disablement evidence and replay, missed traffic from a reader disabled at startup, live post-violation reset, normal traffic, idempotent submit/cancel/resume, abrupt process failure and subsequent progress on the same durable request. The recovery smoke matrix enables full observability and checks both archives' filtered JSON and expiry/inventory changes.

Go, Go formatting/generation, database/devenv tests and Docker were **not executed**, per the user's restriction. Static lexical/import, JSON/YAML, schema/CLI/monitoring contract and diff checks were used; these do not establish compilation or runtime correctness. No git commit or push was run.
