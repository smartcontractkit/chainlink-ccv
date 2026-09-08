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
| One message (or a few known message IDs) has a failed archive row, standalone verifier | `ccv job-queue reschedule` | Step 3 |
| A message was dropped before queue admission (curse, disablement rule, or pending work flushed by a finality violation), or needs fresh source-chain checks | Checkpoint rewind after resolving the cause | Step 4 |
| A range of messages must be reprocessed, or the node runs in CL mode | `ccv chain-statuses set-finalized-height` (checkpoint rewind) | Step 4 |
| A class of traffic (chain, lane, token) must be blocked or unblocked | `aggregator message-disablement-rules` | Step 5 |

**Reschedule does not re-run finality.** It restores the saved payload directly to its
queue, skipping source-event discovery and the source reader's finality, curse, and
disablement admission checks. A `task-verifier` reschedule re-runs verification, including
the policy hook; a `storage-writer` reschedule retries persistence of the existing result.
Use a checkpoint rewind and restart when fresh source-reader checks are required.

`indexer replay` is none of these. It backfills the indexer's own tables from the
aggregator and has no effect on a dropped message. Despite the name, it is not a
message-replay lever.

## 2. Check the Time Windows

Queued jobs have two time windows:

- **Automatic retry: 7 days.** A job that keeps failing retryably is archived when this
  expires. Non-retryable failures, including a policy-hook FAIL, skip the window and are
  archived immediately.
- **Archive retention: 30 days after archiving**, swept every 4 hours. Use `Archived At`,
  not the message's age or `Created At`, to judge proximity to deletion. Once the row is
  deleted, reschedule is no longer possible and a checkpoint rewind is the only remaining
  option.

There is currently no gauge of retained failed jobs by reason, or metric/alert for a job
approaching the retention cutoff. Existing message transition and failure counters describe
events, not the current archive inventory: retries, reschedules, later recovery, and retention
deletions prevent using those counters as a count of messages available to replay.

Check `job-queue list` (step 3) for the retained rows, their `Last Error`, and `Archived At`
before planning around reschedule. Even an archive row is only a recovery candidate: it can
refer to a message already attested by another path, or collide with an active job. Archive
monitoring is follow-up work; the existing retention-alert gap is tracked in CCIP-13332.

## 3. Reschedule a Single Dropped Message

Use when a small number of known message IDs have failed archive rows, for example after a
policy-hook FAIL, and the verifier runs as the standalone binary. Drops before admission
have no archived job to reschedule; use step 4.

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
   verifier ccv job-queue list --queue task-verifier --limit 0
   ```

   Match the message in the `Message ID` column (full hex, `0x` prefixed), and take the
   verifier ID from that row's `Owner ID`. Omitting `--verifier-id` lists all owners in
   this database; it does not infer one owner. Multiple verifier IDs can share a node's
   database, so reschedule requires the explicit owner. If it is already known, add
   `--verifier-id <verifier-id>` to narrow the list.

   `list` defaults to the 50 newest failed rows per queue, ordered by `Created At`;
   `--limit 0` avoids missing older rows. There is no `--message-id` filter, including no
   comma-separated form. To look up several full IDs in the output:

   ```bash
   verifier ccv job-queue list --queue task-verifier --limit 0 |
     grep -Fi -e '0x<full-message-id-1>' -e '0x<full-message-id-2>'
   ```

   A policy-hook drop lands in the `task-verifier` queue; a job that failed while
   persisting a completed verification lands in `storage-writer`.

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
   needed. For `task-verifier`, verification starts over and the policy endpoint is asked
   again. Source-reader finality and admission checks do not run again. For `storage-writer`,
   only the write of the saved result is retried; neither verification nor the policy hook
   is re-run. If the cause remains, processing can fail again. For a policy FAIL, clear the
   cause at the endpoint first (see [policy_hook.md](../../verifier/docs/policy_hook.md),
   "Holding a message for review").
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
7. Confirm recovery for the message ID in its trace or at the aggregator/indexer.
   `storage_write/succeeded` in the transitions metric corroborates lane progress but
   cannot identify this message. From there the executor picks it up as it would a fresh
   message.

Full command reference: [`cli/jobqueue/README.md`](../../cli/jobqueue/README.md).

## 4. Rewind the Checkpoint for a Range

Use when messages were dropped before admission (a curse, disablement rule, or pending work
flushed by a finality violation), when a range needs fresh source-reader checks, when an
archive row is gone, or when the node runs in CL mode and has no `job-queue` command.

### Detect and scope the range

Identify the affected nodes and source chain before changing their checkpoints. A finality
violation disables the reader; it is different from ordinary waiting for confirmations:

```promql
verifier_source_reader_state{
  verifier_id=~"$verifier_id",
  source_chain_name=~"$source_chain_name",
  state="finality_blocked"
} == 1
```

`verifier_source_chain_finality_violated == 1` is another signal of a detected violation.
After a restart, a disabled chain's reader is not started, so current metrics may be absent.
Use metric history and the logs below; inspect `chain-statuses list` once the node is stopped
(the CL command needs the database lock). A disabled row alone does not identify the cause.

For drops before admission, this query shows observed events by node, lane, and reason;
expand the time window to cover the incident:

```promql
sum by (node_id, verifier_id, source_chain_name, dest_chain_name, stage, reason) (
  increase(verifier_message_transitions_total{
    verifier_id=~"$verifier_id",
    source_chain_name=~"$source_chain_name",
    stage=~"admission|pending_finality",
    reason=~"remote_chain_cursed|message_disablement_rule|finality_violation"
  }[1h])
)
```

These are event counts, not a complete list or a count of distinct recoverable messages.
Finality violation transitions count only the pending tasks flushed at detection; messages
arriving while the chain is disabled are not observed. There is no durable list of drops
before admission. Use logs/traces for message IDs; adding IDs as metric labels would create
an unbounded number of time series.

| Cause | Evidence to locate in the affected node's logs | How to scope the source blocks |
| --- | --- | --- |
| Curse | `Dropping task - lane is cursed`, with `messageID`, `sourceChain`, `destChain` | Resolve the IDs to source blocks and include the whole interval during which the verifier observed the curse. |
| Disablement rule | `Dropping task - message matched a disablement rule`, with the same fields | Resolve the IDs to source blocks and cover the rule's effective interval on the verifier, including refresh delay. |
| Finality violation | `FINALITY VIOLATION DETECTED - block hash changed` (`blockNumber`, `storedHash`, `newHash`) or `FINALITY VIOLATION DETECTED - parent hash mismatch` (`blockNumber`, `expectedParent`, `actualParent`), followed by `FINALITY VIOLATION - disabling chain` | Investigate the canonical fork boundary and pending messages; the first detected mismatch is not necessarily the earliest affected block. |

For each known message, get its source block from its canonical transaction receipt, the
discovery trace's `block_number`, or the debug log `Added message to pending queue`
(`messageID`, `blockNumber`). If traces/debug logs are unavailable, query canonical source
message events over the incident interval. Include earlier pending messages, not just
messages emitted after the first drop log. For finality incidents, compare the logged hashes
with canonical RPC headers to establish a last known-good common block and determine which
messages remain valid. Reschedule would reuse the old payload even if its source event was
reorged out; a rewind only rediscovers events present on the canonical chain.

Choose `N` below the earliest affected source block; after a finality violation it must also
be no later than the confirmed common block. The next start reads from **`N + 1`**: to
include block 1200, set `N` to 1199 or earlier. If the boundary cannot be established,
continue the chain/RPC investigation before choosing a height. Record the affected IDs,
nodes/verifier IDs, source selector, evidence for `N`, and a recovery head to check catch-up
against. There is no end-height option: the reader scans all applicable traffic from
`N + 1` toward the head, including other lanes on that source chain.

`Flushed all tasks due to finality violation` reports `pendingFlushed` and `sentFlushed`,
not message IDs. It clears the reader's in-memory tracking; it does **not** remove already
published database jobs or undo attestations. Inspect those jobs/results separately. A
disablement rejection at the aggregator write stage likewise concerns work already admitted
to the queues, rather than a source-reader drop.

### Apply the rewind

Resolve the cause first: confirm the canonical chain/RPC view after a finality violation,
or clear the curse/rule and allow the verifier to observe that change. Rewind re-enters
source-reader admission using current chain data. Restart creates a fresh finality checker;
it does not reconstruct the checker's pre-restart block-hash history or undo prior results.

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

   Use the `N` established above. If the chain was disabled, also enable the same
   chain/verifier pair while the node is stopped:

   ```bash
   # CL mode
   chainlink node ccv chain-statuses enable \
     --chain-selector <selector> --verifier-id <verifier-id>
   # standalone verifier
   verifier ccv chain-statuses enable \
     --chain-selector <selector> --verifier-id <verifier-id>
   ```

   The finality-violation handler writes `disabled = true` and a checkpoint of `0`; that
   value is not the incident's fork boundary. Set the investigated height as well as enabling
   the chain, rather than only enabling and unintentionally reading from block 1. Verify
   both fields with `chain-statuses list` before starting.
3. Start the node. The source reader re-reads from `N + 1` and applies admission checks
   again. Messages in the range that were already attested can be verified again. An
   admitted message gets a job unless a matching active job already exists; any old failed
   archive row remains (step 3.2). Confirm `Resuming from chainStatus` reports the intended
   `startBlock`, the reader returns to `running` and catches up, and the affected message
   IDs reach the aggregator/indexer.

Command reference: [`cli/chainstatuses/README.md`](../../cli/chainstatuses/README.md).

## 5. Block or Unblock a Class of Traffic

Use aggregator message-disablement rules when the unit of work is a chain, lane, or token
rather than an individual message. Reference:
[`aggregator/cli/messagedisablement/README.md`](../../aggregator/cli/messagedisablement/README.md).

- Rules take effect on the aggregator's `messageDisablementRules.refreshInterval`, not
  immediately.
- Deleting the rule is the un-block; allow both the aggregator and verifier to refresh.
  This does not recover messages already dropped by source-reader admission. Rewind the
  affected source range as described in step 4 after the rule clears.

## 6. Known Limitations

Current limitations; see CCIP-13332 for existing recovery follow-up work:

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
- `task-verifier` reschedule re-runs the policy hook, but skips source-reader admission
  (including finality). `storage-writer` reschedule retries only persistence. There is no
  verifier-side per-message bypass for a persistently failing endpoint short of removing
  `[policy_hook]` from config and
  restarting, which disables screening for all traffic on that node. The supported pattern
  is for the operator's endpoint to answer PASS for the message, then reschedule
  ([policy_hook.md](../../verifier/docs/policy_hook.md), "Holding a message for review").
- Nothing reconciles the archive against later recovery, so a message recovered by a rewind
  keeps its failed row until the retention sweep.
- No gauge counts retained failed jobs by reason, and no metric or alert warns before the
  30-day archive retention deletes a dropped message. These need archive-aware monitoring.
- No durable command lists messages dropped before queue admission with their reasons and
  block numbers. Step 4 uses existing metrics, logs, traces, and source-chain evidence;
  a queryable drop history would require additional persistence.
