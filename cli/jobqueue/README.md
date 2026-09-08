# CCV job-queue CLI

CLI commands to inspect failed jobs in the verifier's archive tables and move them back to the active queue. This is the manual replay lever for a single dropped message.

## Where it is available

The commands are wired into the standalone `verifier` binary under `verifier ccv job-queue` (`cmd/verifier/run_ccv_cli.go`). The Chainlink node binary does not expose them: its `chainlink node ccv` group carries only `chain-statuses` (chainlink core `core/cmd/shell_local.go`, `initCCVCommand`, develop as of 2026-09-04). A verifier running in CL mode falls back to the checkpoint rewind in `ccv chain-statuses`; see the [remediation runbook](../../docs/runbooks/remediating-stuck-or-dropped-messages.md).

## Commands

| Command | Description |
|---------|-------------|
| `list` | List failed jobs in the archive tables (table: Queue, Job ID, Message ID, Owner ID, Chain Selector, Attempts, Last Error, Created At, Archived At), newest first by `created_at`. |
| `reschedule` | Move a failed job from the archive back to the active queue as `pending`, with the attempt count reset and a fresh retry deadline. |

`list` accepts (all optional):

- `--queue` – filter by queue: `task-verifier` or `storage-writer`; omit to list both
- `--verifier-id` – filter by job owner; omit to list all verifiers on this database
- `--limit` – maximum jobs to show per queue (default 50; 0 = unlimited)

There is no `--message-id` filter. To find several IDs, list with `--limit 0` and filter
the output using full IDs, for example `grep -Fi -e '0x<id-1>' -e '0x<id-2>'`.
Omitting `--verifier-id` lists all owners; it does not infer which owner to reschedule.

`reschedule` requires:

- `--queue` – `task-verifier` or `storage-writer`
- `--verifier-id` – verifier ID (owner) that owns the job
- `--job-id` or `--message-id` – exactly one of the two; `--message-id` takes hex with or without a `0x` prefix

Take `--verifier-id` from the matching row's `Owner ID`. A node's database can contain
multiple verifier owners, including jobs for the same message, so running the command on
the node does not uniquely identify the owner.

`reschedule` also accepts:

- `--retry-duration` – how long from now the job is eligible for retry; sets the new `retry_deadline` (default 1h)

## Usage

Set `CL_DATABASE_URL` (or `[db].url` in the verifier secrets file) to the verifier's PostgreSQL connection string, then:

```bash
verifier ccv job-queue list
verifier ccv job-queue list --queue task-verifier --verifier-id <id> --limit 0
verifier ccv job-queue reschedule --queue task-verifier --verifier-id <id> --message-id 0x...
```

In devenv or any Docker deployment: `docker exec <verifier-container> /bin/verifier ccv job-queue ...`.

## Operator notes

- Reschedule works against a **running** node. The CLI cannot signal the in-process consumer, so the job waits for the queue's fallback poll, `DefaultPendingFallbackInterval` (30s) in `verifier/pkg/jobqueue/signal.go`. No shutdown or restart is needed, unlike `ccv chain-statuses`.
- Reschedule restores the saved payload directly to the selected queue. It does **not** re-read source events or re-run the source reader's finality, curse, or disablement admission checks. `task-verifier` re-runs verification and the policy hook; `storage-writer` retries persistence of the saved result without re-running verification or the hook. Resolve the original cause first.
- Messages dropped before admission, including pending tasks flushed by a finality violation, have no failed archive row to list or reschedule. To recover them or request fresh source-reader checks, use a checkpoint rewind and restart as described in the [remediation runbook](../../docs/runbooks/remediating-stuck-or-dropped-messages.md#4-rewind-the-checkpoint-for-a-range).
- A message dropped by N committee members needs one reschedule per affected member, against that member's database. `--verifier-id` takes exactly one value, so where several verifier IDs share a database it is also one command per verifier ID.
- Jobs that fail retryably are archived after a 7-day automatic retry window; non-retryable failures (such as a policy-hook FAIL) are archived immediately. Archived rows are deleted 30 days after archiving (swept every 4 hours). After that the job cannot be rescheduled and rewinding the source-chain checkpoint (`ccv chain-statuses set-finalized-height`) is the only remaining option.
- Errors are surfaced, not swallowed. Rescheduling a job that is not in the archive (already rescheduled, wrong owner, wrong ID) fails with an error rather than silently succeeding. The move is a single statement, so the archive row is only deleted if the active row is inserted.
- The active tables have a unique key on `(owner_id, chain_selector, message_id)`. If an active job for the message already exists, or two archived failed rows match one `--message-id`, the command errors and nothing changes; use `--job-id` to pick a single row.
- The archive is not reconciled against later recovery. A message recovered by a checkpoint rewind keeps its failed row until the retention sweep; check the aggregator or indexer before rescheduling it.
- There is no current archive inventory gauge or retention-expiry alert. Transition/failure counters count events, not retained failed rows or distinct messages available to replay. Inspect `Archived At` to judge the 30-day retention window.

For choosing between this and the other recovery levers, see the
[remediation runbook](../../docs/runbooks/remediating-stuck-or-dropped-messages.md).
