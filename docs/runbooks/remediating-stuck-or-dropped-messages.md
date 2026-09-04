# Runbook: Remediating a Stuck or Dropped Message

## Scenario

A triage runbook — [Message Unverified After 15 Minutes](./unverified-message-after-15-minutes.md)
or [Message Unexecuted After 15 Minutes](./unexecuted-message-after-15-minutes.md) — has
identified a stuck or dropped message and its scope. This runbook picks the recovery lever.

> **Status of the levers, as of 2026-09-04.** Checkpoint rewind has been run in production
> (testnet). `job-queue reschedule` is covered by unit tests and a CLI smoke test and works
> against a running node, but the full drop → reschedule → signed path has not been exercised
> end to end, and the command has not been run in production. If you use it during a real
> incident, treat the first run as a validation exercise and record the outcome in the
> incident notes.

## 1. Pick the Lever

| Problem | Lever | Go to |
| --- | --- | --- |
| One message (or a few known message IDs) was dropped | `ccv job-queue reschedule` | Step 3 |
| A range of messages must be reprocessed | `ccv chain-statuses set-finalized-height` (checkpoint rewind) | Step 4 |
| A class of traffic (chain, lane, token) must be blocked or unblocked | `aggregator message-disablement-rules` | Step 5 |

`indexer replay` is none of these: it backfills the indexer's own tables from the
aggregator and has no effect on a dropped message. Despite the name, it is not a
message-replay lever.

## 2. Check the Time Windows

Two compile-time constants bound every option:

- **Automatic retry: 7 days.** A job that keeps failing retryably is archived when this
  expires. Non-retryable failures — including a policy-hook FAIL — skip the window and are
  archived immediately.
- **Archive retention: 30 days**, swept every 4 hours. Once the archived row is deleted,
  reschedule is no longer possible and a checkpoint rewind is the only remaining option.

There is currently no metric or alert for an archived job approaching the retention cutoff
(tracked in CCIP-13332). If you are working a dropped message older than about three weeks,
confirm the archive row still exists (`job-queue list`, step 3) before planning around
reschedule.

## 3. Reschedule a Single Dropped Message

Use when a small number of known message IDs were dropped, for example by a policy-hook
FAIL.

1. Resolve which verifiers dropped the message. Metrics deliberately have no `message_id`
   label; use Atlas, the indexer, or the message trace viewer to map the message ID to
   verifier IDs. Each committee member evaluated and dropped the message on its own verdict,
   so expect to repeat the remaining steps once per member, against that member's database.
2. On each affected verifier, confirm the archived job exists:

   ```bash
   # Chainlink node
   chainlink node ccv job-queue list --queue task-verifier --verifier-id <verifier-id>
   # standalone verifier (CL_DATABASE_URL set)
   verifier ccv job-queue list --queue task-verifier --verifier-id <verifier-id>
   ```

   Match the message in the `Message ID` column. A policy-hook drop lands in the
   `task-verifier` queue; a job that failed while persisting a completed verification lands
   in `storage-writer`.
3. Reschedule it:

   ```bash
   chainlink node ccv job-queue reschedule \
     --queue task-verifier --verifier-id <verifier-id> --message-id 0x...
   ```

   `--retry-duration` (default 1h) sets how long the node keeps retrying before the job is
   archived again.
4. What to expect: the job returns to the active queue as `pending` with its attempt count
   reset, and the running node picks it up on its next poll — no restart needed. Processing
   starts over, including the policy hook: the endpoint is asked again. If the cause of the
   original failure still exists, the job fails again and returns to the archive; reschedule
   is not a bypass. For a policy FAIL, clear the cause at the endpoint first (see
   [policy_hook.md](../../verifier/docs/policy_hook.md), "Holding a message for review").
5. Re-running the command is safe: if the job is no longer in the archive (already
   rescheduled, wrong owner, wrong ID) the command errors instead of silently succeeding.
6. Confirm recovery: the message transitions metric reaches `storage_write/succeeded`
   (triage runbook, step 7), or the message becomes visible at the aggregator/indexer.

Full command reference: [`cli/jobqueue/README.md`](../../cli/jobqueue/README.md).

## 4. Rewind the Checkpoint for a Range

Use when a range of messages must be reprocessed — recovery from a finality violation or a
curse window — or when the archive row for a dropped message is already gone.

1. Stop the node first. The change takes effect on the next start; in CL mode the running
   process holds a DB lease, which the deploy chart's `pauseNode` exists to release (see the
   chainlink-cluster chart README in `chainlink-ccv-deploy`).
2. Rewind the checkpoint:

   ```bash
   chainlink node ccv chain-statuses set-finalized-height \
     --chain-selector <selector> --verifier-id <verifier-id> --block-height <N>
   ```

   Choose `N` below the earliest block the affected messages were read from. If the chain
   was disabled (for example after a finality violation), re-`enable` it as well.
3. Start the node. The source reader re-reads from `N` and every message in the range is
   processed again — size the rewind accordingly; this is deliberately not a per-message
   lever.

Command reference: [`cli/chainstatuses/README.md`](../../cli/chainstatuses/README.md).

## 5. Block or Unblock a Class of Traffic

Use aggregator message-disablement rules when the unit of work is a chain, lane, or token
rather than an individual message. Reference:
[`aggregator/cli/messagedisablement/README.md`](../../aggregator/cli/messagedisablement/README.md).

- Rules take effect on the aggregator's `messageDisablementRules.refreshInterval`, not
  immediately.
- Deleting the rule is the un-block; traffic resumes after the next refresh.

## 6. Known Limitations

Tracked under CCIP-13332:

- No command maps a message ID to the verifier IDs that dropped it; discovery is an
  Atlas/indexer lookup by hand.
- `--verifier-id` takes a single value and each member has its own database, so
  committee-wide recovery is one command per member. In the CLL deploy repo this is
  expressed as a `jobs` list in the chainlink-cluster chart.
- `reschedule` re-runs the policy hook; there is no per-message bypass for a persistently
  failing endpoint short of removing `[policy_hook]` from config and restarting, which
  disables screening for all traffic on that node.
- No metric or alert warns before the 30-day archive retention deletes a dropped message.
