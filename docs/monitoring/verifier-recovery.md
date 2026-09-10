# Verifier recovery monitoring

Import [Verifier Recovery](../../build/devenv/dashboards/verifier_recovery.json) into Grafana using the existing Prometheus-compatible `victoriametrics` datasource UID. The JSON lives alongside the other devenv dashboard assets. Point that datasource at your deployment's metric backend or replace the UID before import.

The [Grafana alert provisioning file](./verifier-recovery-alerts.yaml) defines a retention warning, collection-health warning and audit-failure warning, each linked to the [remediation runbook](../runbooks/remediating-stuck-or-dropped-messages.md). Mount it under Grafana's `provisioning/alerting` directory or import it through your existing provisioning workflow. Set the organization, datasource UID and notification-policy routing for your deployment. This change supplies the rules; it does not modify a live Grafana installation or contact point.

## Archive inventory contract

| Metric | Meaning |
| --- | --- |
| `verifier_archive_failed_jobs` | Current retained rows with `status='failed'`; completed rows are excluded. |
| `verifier_archive_expiring_jobs` | Failed rows archived at least 23 days ago, seven days before eligibility for the unchanged 30-day cleanup. Overdue retained rows remain included until removed. |
| `verifier_archive_oldest_age_seconds` | Age of the oldest failed row measured from archive `completed_at`, not job creation. |
| `verifier_archive_collection_success` | 1 after a successful collection, 0 after failure. |
| `verifier_archive_last_success_timestamp` | Unix timestamp of the last successful collection. |

Inventory labels are `queue` (`task-verifier`/`storage-writer`), `verifier_id`, `source_chain` (decimal selector) and bounded `reason`. Collection health uses queue/owner. Normal telemetry resource labels, including node identity, continue to apply. No message/job ID, transaction hash, rule ID or raw error is a metric label.

Persisted reasons are `policy_rejected`, `retry_window_expired`, `validation_error`, `storage_failure` and `unknown`. Existing failed archives default to unknown. The full stored error remains available in CLI JSON. These categories aid triage; they are not policy decisions or proof a saved payload is canonical.

Collection starts with the service and repeats every minute with a two-second query deadline. A failed query emits health 0 while leaving last-good inventory unchanged. On success, removed groups emit zero. After a process restart inventory is rebuilt from the archives; an initially empty group has no series until first observed. Treat absent inventory as zero only when collection health is present and fresh. The dashboard deliberately keeps health and freshness visible instead of filling every missing value with zero.

The expiry rule gates on successful collection within three minutes. The separate health rule detects query failure/staleness (retaining timestamp evidence for 15 minutes) or total collector absence. Keep your normal scrape-target/process-availability alerts: this rule cannot discover an expected owner/queue that has never emitted a series, or indefinitely identify one missing owner among healthy owners.

## Recovery and coverage

`verifier_recovery_operations` and `verifier_recovery_remaining_blocks` describe retained operations by owner/source and one of six states: accepted, running, completed, cancelled, failed, blocked. They are refreshed with the reader heartbeat every 30 seconds, with zeros for empty states. `verifier_recovery_collection_success` and `verifier_recovery_last_success_timestamp` expose failure/staleness. The cumulative `verifier_recovery_audit_failures_total` counts failed evidence-write batches, not lost-message totals.

Use `ccv recovery status` for one operation's precise counters and error, and `ccv recovery events` for message-level evidence and coverage. The reader's registry records audit-failure counts at its next successful heartbeat. A crash before persistence can lose those counts; logs/metrics and canonical source investigation still matter. Never interpret empty event history as a complete inventory of traffic missed while disabled.

## Collection cost and validation

Migration 00009 adds partial covering indexes on `(owner_id, chain_selector, failure_category, completed_at)` for failed rows in each archive. Queries filter the current owner before grouping and never decode saved JSON payloads or classify raw errors at scrape time. Archive scans run once per minute, separate from the existing ten-second active-queue size polling.

`TestArchiveInventoryRepresentativePlan` seeds 100,000 failed rows across 100 owners, collects `EXPLAIN (ANALYZE, BUFFERS)` and checks that the inventory index is selected. The fixture logs execution time/buffers when run; it has not been executed during this change because Go and Docker execution were prohibited. No measured production latency is claimed. Before deployment, run that fixture and evaluate it with representative owner skew and retained archive size; the two-second deadline makes overload visible rather than silently reporting zero inventory.

Database tests cover failure/success/expiry categories, completed-row exclusion, removal after reschedule/cleanup and reconstruction after restart. The devenv recovery matrix enables the full observability stack and checks both queues' exact JSON lookup and inventory/expiry metrics as fixtures are restored and removed. Runtime tests, including that matrix, must be run in an environment where Go/Docker execution is authorized.
