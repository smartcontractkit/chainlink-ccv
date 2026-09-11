# Verifier source recovery monitoring

Import [Verifier Source Recovery](../../build/devenv/dashboards/verifier_recovery.json) into
Grafana using the `victoriametrics` datasource UID, and the
[alert provisioning file](./verifier-recovery-alerts.yaml) for the audit-failure warning.
Retained failed-job inventory is a separate concern; see
[archive inventory monitoring](./verifier-archive-inventory.md).

## Recovery and coverage

`verifier_recovery_operations` and `verifier_recovery_remaining_blocks` describe retained operations by owner/source and one of six states: accepted, running, completed, cancelled, failed, blocked. They are refreshed with the reader heartbeat every 30 seconds, with zeros for empty states. `verifier_recovery_collection_success` and `verifier_recovery_last_success_timestamp` expose failure/staleness. The cumulative `verifier_recovery_audit_failures_total` counts failed evidence-write batches, not lost-message totals.

Use `ccv recovery status` for one operation's precise counters and error, and `ccv recovery events` for message-level evidence and coverage. The reader's registry records audit-failure counts at its next successful heartbeat. A crash before persistence can lose those counts; logs/metrics and canonical source investigation still matter. Never interpret empty event history as a complete inventory of traffic missed while disabled.
