# CCV job-queue CLI

CLI commands to inspect failed jobs in the verifier's archive tables and move them back to the active queue. This is the manual replay lever for a single dropped message.

## Commands

| Command | Description |
|---------|-------------|
| `list` | List failed jobs in the archive tables (table: Queue, Job ID, Message ID, Owner ID, Chain Selector, Attempts, Last Error, Created At, Archived At). |
| `reschedule` | Move a failed job from the archive back to the active queue as `pending`, with the attempt count reset and a fresh retry deadline. |

`list` accepts (all optional):

- `--queue` – filter by queue: `task-verifier` or `storage-writer`; omit to list both
- `--verifier-id` – filter by job owner; omit to list all verifiers on this database
- `--limit` – maximum jobs to show per queue (default 50; 0 = unlimited)

`reschedule` requires:

- `--queue` – `task-verifier` or `storage-writer`
- `--verifier-id` – verifier ID (owner) that owns the job
- `--job-id` or `--message-id` – exactly one of the two; `--message-id` takes hex with or without a `0x` prefix

`reschedule` also accepts:

- `--retry-duration` – how long from now the job is eligible for retry; sets the new `retry_deadline` (default 1h)

## Usage

**Chainlink node**

```bash
chainlink node ccv job-queue list
chainlink node ccv job-queue list --queue task-verifier --verifier-id <id>
chainlink node ccv job-queue reschedule --queue task-verifier --verifier-id <id> --message-id 0x...
```

**Standalone verifier**

Set `CL_DATABASE_URL` to the verifier's PostgreSQL connection string, then:

```bash
verifier ccv job-queue list
verifier ccv job-queue reschedule --queue task-verifier --verifier-id <id> --message-id 0x...
```

## Operator notes

- Reschedule works against a **running** node; the job is picked up on the next queue poll. (Unlike `ccv chain-statuses`, no shutdown or restart is needed.)
- A rescheduled job is reprocessed from scratch: whatever failed the first time runs again, including the policy hook. There is no bypass — if the cause of the failure still exists, the job fails again and returns to the archive.
- Each verifier owns its own database. A message dropped by N committee members needs one reschedule per member, against that member's database. `--verifier-id` takes exactly one value.
- Jobs that fail retryably are archived after a 7-day automatic retry window; non-retryable failures (such as a policy-hook FAIL) are archived immediately. Archived rows are deleted 30 days after archiving (swept every 4 hours), after which the job cannot be rescheduled — rewinding the source-chain checkpoint (`ccv chain-statuses set-finalized-height`) is the only remaining option.
- Errors are surfaced, not swallowed: rescheduling a job that is not in the archive (already rescheduled, wrong owner, wrong ID) fails with an error rather than silently succeeding.

For choosing between this and the other recovery levers, see the
[remediation runbook](../../docs/runbooks/remediating-stuck-or-dropped-messages.md).
