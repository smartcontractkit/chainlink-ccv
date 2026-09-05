# Runbook: Remediating a Stuck or Dropped Message

## Scenario

A triage runbook ([Message Unverified After 15 Minutes](./unverified-message-after-15-minutes.md)
or [Message Unexecuted After 15 Minutes](./unexecuted-message-after-15-minutes.md)) has
identified a stuck or dropped message and its scope. This runbook picks the recovery lever.

> **Status of the levers, as of 2026-09-04.**
>
> Checkpoint rewind has been run in production (testnet), through the chainlink-cluster
> chart's `jobs` list with `pauseNode: true`.
>
> `job-queue reschedule` is exercised end to end in devenv: `TestE2ESmoke_PolicyHook`
> (phase `fail drops and reschedule recovers`) drops a real message on a policy FAIL,
> reschedules it on every committee member with the node still running, and asserts the
> message is signed. It runs in CI. It has not been run in production yet, so treat the
> first production use as a validation exercise and record the outcome in the incident
> notes.
>
> `job-queue` exists only in the standalone `verifier` binary. The Chainlink node's `ccv`
> command group exposes `chain-statuses` alone (chainlink core `core/cmd/shell_local.go`,
> `initCCVCommand`, develop as of 2026-09-04). A node running in CL mode has no per-message
> reschedule today; its only lever is the checkpoint rewind in step 4. Wiring `job-queue`
> into the node binary is a chainlink core change, tracked under CCIP-13332.

## 1. Pick the Lever

| Problem | Lever | Go to |
| --- | --- | --- |
| One message (or a few known message IDs) was dropped, standalone verifier | `ccv job-queue reschedule` | Step 3 |
| A range of messages must be reprocessed, or the node runs in CL mode | `ccv chain-statuses set-finalized-height` (checkpoint rewind) | Step 4 |
| A class of traffic (chain, lane, token) must be blocked or unblocked | `aggregator message-disablement-rules` | Step 5 |

`indexer replay` is none of these. It backfills the indexer's own tables from the
aggregator and has no effect on a dropped message. Despite the name, it is not a
message-replay lever.

## 2. Check the Time Windows

Two compile-time constants bound every option:

- **Automatic retry: 7 days.** A job that keeps failing retryably is archived when this
  expires. Non-retryable failures, including a policy-hook FAIL, skip the window and are
  archived immediately.
- **Archive retention: 30 days**, swept every 4 hours. Once the archived row is deleted,
  reschedule is no longer possible and a checkpoint rewind is the only remaining option.

There is currently no metric or alert for an archived job approaching the retention cutoff
(tracked in CCIP-13332). If you are working a dropped message older than about three weeks,
confirm the archive row still exists (`job-queue list`, step 3) before planning around
reschedule.

## 3. Reschedule a Single Dropped Message

Use when a small number of known message IDs were dropped, for example by a policy-hook
FAIL, and the verifier runs as the standalone binary.

1. Resolve which verifiers dropped the message. Metrics deliberately have no `message_id`
   label; use Atlas, the indexer, or the message trace viewer to map the message ID to
   verifier IDs. For a policy-hook FAIL it is every member whose endpoint answered FAIL,
   which on a single-operator committee is every member, since each one asked the endpoint
   and dropped the message on its own verdict. Expect to repeat the remaining steps once per
   member, against that member's database.
2. On each affected verifier, confirm the archived job exists. `CL_DATABASE_URL` (or
   `[db].url` in the verifier secrets file) must point at that verifier's database. In
   devenv or any Docker deployment the command runs as
   `docker exec <verifier-container> /bin/verifier ccv ...`.

   ```bash
   verifier ccv job-queue list --queue task-verifier --verifier-id <verifier-id>
   ```

   Match the message in the `Message ID` column (full hex, `0x` prefixed). `list` shows the
   50 newest failed rows per queue by default, newest first. Pass `--limit 0` when the
   message is old or the node is busy, and grep the output, since there is no
   `--message-id` filter. A policy-hook drop lands in the `task-verifier` queue; a job that
   failed while persisting a completed verification lands in `storage-writer`.

   If the message has since been attested by another path (a checkpoint rewind, for
   instance), its failed row is still in the archive: nothing reconciles the archive against
   later recovery. Check the aggregator or indexer for a result before rescheduling, and
   leave an attested message's row alone. It ages out with the retention sweep.
3. Reschedule it:

   ```bash
   verifier ccv job-queue reschedule \
     --queue task-verifier --verifier-id <verifier-id> --message-id 0x...
   ```

   `--retry-duration` (default 1h) sets how long the node keeps retrying before the job is
   archived again.
4. What to expect: the job returns to the active queue as `pending` with its attempt count
   reset, and the running node picks it up within about 30 seconds. That is the queue's
   fallback poll, `DefaultPendingFallbackInterval` in `verifier/pkg/jobqueue/signal.go`; the
   CLI cannot signal the in-process consumer, so the row waits for that poll. No restart is
   needed. Processing starts over, including the policy hook: the endpoint is asked again.
   If the cause of the original failure still exists, the job fails again and returns to the
   archive; reschedule is not a bypass. For a policy FAIL, clear the cause at the endpoint
   first (see [policy_hook.md](../../verifier/docs/policy_hook.md), "Holding a message for
   review").
5. Re-running the command is safe. If the job is no longer in the archive (already
   rescheduled, wrong owner, wrong ID) the command errors instead of silently succeeding.
   The move is one SQL statement, so the archive row is only deleted when the active row is
   inserted; a failure leaves the archive as it was.
6. Two ways `--message-id` can refuse, both on the active table's unique key
   `(owner_id, chain_selector, message_id)`. If an active job for the same message already
   exists (a rewind re-read it and it is pending or processing), the command errors and the
   message is already on its way, so stop. If two archived failed rows match the message
   (dropped, re-read by a rewind, dropped again), the command tries to restore both, the
   second insert hits the same key, and nothing changes; pick one row with `--job-id`.
7. Confirm recovery: the message transitions metric reaches `storage_write/succeeded`
   (triage runbook, step 7), or the message becomes visible at the aggregator/indexer. From
   there the executor picks it up as it would a fresh message.

Full command reference: [`cli/jobqueue/README.md`](../../cli/jobqueue/README.md).

## 4. Rewind the Checkpoint for a Range

Use when a range of messages must be reprocessed (recovery from a finality violation or a
curse window), when the archive row for a dropped message is already gone, or when the node
runs in CL mode and has no `job-queue` command.

1. Stop the node first. The change takes effect on the next start. In CL mode there is a
   second reason: every `chainlink node ccv` command opens the node database with the node's
   own lock, so it cannot run while the node holds the lease. The chainlink-cluster chart's
   `jobs` list with `pauseNode: true` does the stop, run, restart sequence for a CLL
   deployment (see the chart README in `chainlink-ccv-deploy`).
2. Rewind the checkpoint:

   ```bash
   # CL mode
   chainlink node ccv chain-statuses set-finalized-height \
     --chain-selector <selector> --verifier-id <verifier-id> --block-height <N>
   # standalone verifier
   verifier ccv chain-statuses set-finalized-height \
     --chain-selector <selector> --verifier-id <verifier-id> --block-height <N>
   ```

   Choose `N` below the earliest block the affected messages were read from. If the chain
   was disabled (for example after a finality violation), re-`enable` it as well.
3. Start the node. The source reader re-reads from `N` and every message in the range is
   processed again, so size the rewind accordingly; this is deliberately not a per-message
   lever. Messages in the range that were already attested are verified again. A dropped
   message in the range gets a new job, and its old failed row stays in the archive (step
   3.2).

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

- The Chainlink node binary has no `job-queue` command. In CL mode the only recovery for a
  dropped message is the checkpoint rewind, node stopped.
- No command maps a message ID to the verifier IDs that dropped it across nodes. Per
  database, `job-queue list` without `--verifier-id` shows every owner's failed rows; the
  cross-node step is an Atlas/indexer lookup by hand. `list` has no `--message-id` filter
  and shows 50 rows per queue by default.
- `--verifier-id` takes a single value. Where several verifier IDs share one database
  (prod-testnet nodes host two), recovery is one command per verifier ID per database. The
  cross-node fan-out belongs to the deploy layer: the chainlink-cluster chart runs one
  `commands` list across `targetNodes`.
- `reschedule` re-runs the policy hook. There is no verifier-side per-message bypass for a
  persistently failing endpoint short of removing `[policy_hook]` from config and
  restarting, which disables screening for all traffic on that node. The supported pattern
  is for the operator's endpoint to answer PASS for the message, then reschedule
  ([policy_hook.md](../../verifier/docs/policy_hook.md), "Holding a message for review").
- Nothing reconciles the archive against later recovery, so a message recovered by a rewind
  keeps its failed row until the retention sweep.
- No metric or alert warns before the 30-day archive retention deletes a dropped message.
