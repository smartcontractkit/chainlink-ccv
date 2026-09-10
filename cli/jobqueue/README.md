# CCV job-queue CLI

Inspect retained failed jobs and restore a saved payload while the standalone verifier stays running. Point `CL_DATABASE_URL` or the verifier secrets file at the affected member's database. Repeat recovery for each affected committee member.

## Find failed jobs

```bash
verifier ccv job-queue list --queue task-verifier --message-id 0x<FULL_ID>
verifier ccv job-queue list --message-id 0x<FULL_ID_1>,0x<FULL_ID_2> \
  --message-id 0x<FULL_ID_3> --output json --limit 0
```

| Flag | Behavior |
| --- | --- |
| `--queue` | `task-verifier` or `storage-writer`; omitted searches both. |
| `--verifier-id` | One owner; omitted searches all owners in this database. |
| `--message-id` | Repeated or comma-separated full 32-byte hexadecimal IDs. Prefix and case are normalized; duplicates collapse. Empty elements, short IDs and malformed hex fail before querying. |
| `--limit` | Newest 50 failed rows **per queue** by default; `0` means unlimited. Filters apply in SQL before ordering and limiting. Negative values fail. |
| `--output` | `table` (default) or `json`. JSON contains an array, including `[]` for no matches. |

Without a message filter, listing retains its previous behavior. Ordering is by original `created_at` descending, then job ID. A filtered lookup can find a matching row older than the newest 50 unfiltered rows.

JSON includes `queue`, `job_id`, full `message_id`, `owner_id`, decimal-string `source_chain_selector`, `attempts`, full `last_error`, persisted `failure_category`, `created_at`, `archived_at`, and `retry_deadline`. Timestamps are RFC3339; an absent archive timestamp is null and an absent error is an empty string. Diagnostics go to stderr, leaving stdout suitable for JSON consumers. Large selectors retain their exact value in JavaScript clients. The table can shorten diagnostic text; use JSON for complete errors.

## Restore a saved job

```bash
verifier ccv job-queue reschedule --queue task-verifier \
  --message-id 0x<FULL_ID> --retry-duration 1h
verifier ccv job-queue reschedule --queue storage-writer \
  --verifier-id <OWNER> --job-id <UUID>
```

Supply exactly one message ID or job ID and one queue. The optional owner is resolved only from matching **failed archive rows in that queue**:

- No matching owner: fail without changing data.
- One owner and one job: restore and print the resolved owner.
- Several owners: list the matching owners and require `--verifier-id`.
- Several jobs for the same owner/message: require `--job-id` to select one.

An explicit owner is always honored; a wrong owner never falls back to another owner. Selection, archive removal and insertion share a transaction with row locking. A concurrent restore or a conflicting active `(owner_id, chain_selector, message_id)` cannot delete the archive without restoring a job.

The restored job is pending with attempts reset and a new positive retry duration (default 1 hour). The running verifier normally picks it up on its queue fallback poll within about 30 seconds. `task-verifier` runs verification and policy again. `storage-writer` retries writing the saved result. Neither path re-reads source events or repeats source-reader finality, curse or disablement admission checks.

For changed canonical source data, pre-admission drops or expired archives, use [live source recovery](../recovery/README.md). Replayed and already attested messages are not reconciled against old archive rows; verify the aggregator/indexer result before restoring a candidate.

## Retention and monitoring

Automatic retry remains 7 days. Non-retryable failures archive immediately. Archive cleanup remains 30 days after `archived_at` (`completed_at` in SQL), swept every 4 hours.

Both queues now export retained failed inventory once per minute, with a 7-day warning lead (archive age at least 23 days). Categories are persisted when archiving: `policy_rejected`, `retry_window_expired`, `validation_error`, `storage_failure`, and `unknown`. Known validation/deserialization errors take precedence over generic storage failures; expired retries use `retry_window_expired`. Pre-upgrade rows retain `unknown`. Classification is advisory and never determines whether a replay is safe.

See [monitoring and alert provisioning](../../docs/monitoring/verifier-recovery.md) and the [remediation runbook](../../docs/runbooks/remediating-stuck-or-dropped-messages.md). Inventory counts retained failed **jobs**, which may contain repeated or already recovered messages; it does not count distinct affected messages.
