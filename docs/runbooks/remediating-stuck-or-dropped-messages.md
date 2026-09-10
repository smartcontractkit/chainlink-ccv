# Runbook: Remediating a Stuck or Dropped Message

_Last reviewed: 2026-09-10._

Use after [unverified-message triage](./unverified-message-after-15-minutes.md) or [unexecuted-message triage](./unexecuted-message-after-15-minutes.md) identifies the affected owner, source and messages. Recovery is per affected committee member and database. Cross-node discovery/fan-out remains an operator or deployment-layer responsibility.

## 1. Pick the Lever

| Problem | Recovery |
| --- | --- |
| Failed archived verification, valid saved source payload | `ccv job-queue reschedule --queue task-verifier`; verification and policy run again. |
| Failed persistence of a valid completed result | `ccv job-queue reschedule --queue storage-writer`; only persistence runs again. |
| Curse/rule drop before admission, expired archive, missed source interval, or canonicality needs checking | `ccv recovery replay`; bounded canonical source re-read and current admission checks while the reader stays live. |
| Reader disabled by a finality violation or at startup | Investigate canonical boundary, then `ccv recovery reset-reader`; explicit recorded reset and bounded source recovery. |
| Deployment/binary lacks the recovery CLI or upgraded reader | Stop, set checkpoint, optionally enable, start; legacy fallback in step 4. |
| Block/unblock a class of traffic | Aggregator disablement rules (step 5), followed by source recovery for already dropped traffic. |

**Reschedule uses the saved payload and skips source-reader finality, curse and disablement admission checks.** It is unsuitable for deciding whether an event remains canonical after a reorg. Source recovery re-reads events that still exist on the chain and enters ordinary verification/policy processing after admission. Neither path bypasses policy. Indexer backfill refreshes the indexer's view of results; it does not re-admit verifier source events or retry policy decisions.

## 2. Check the Time Windows

Automatic retry remains **7 days**, with non-retryable failures (including policy FAIL) archived immediately. Archive retention remains **30 days after archiving**, swept every 4 hours. The message's creation time does not start that retention window.

The Verifier Recovery dashboard reports current retained failed jobs by queue, owner, source and bounded failure category. A warning starts at 23 days of archive age, giving seven days before eligibility for deletion. Collection runs once per minute. Check collection success and freshness before interpreting inventory. [Monitoring reference and provisionable alerts](../monitoring/verifier-recovery.md) include the retention warning and collector-health alert.

Inventory is a count of failed **jobs**, including repeated or already recovered messages, not a distinct affected-message count or proof that reschedule is safe. Successful collection clears disappeared groups after reschedule/cleanup. Failed collection keeps the last good inventory and exposes failure/staleness; do not interpret a database outage as zero jobs.

Drop evidence is separate from archives. It is retained for 30 days since its last observation and includes coverage limitations. Expired archive rows can no longer be rescheduled; source recovery remains possible when canonical source data is available.

## 3. Reschedule a Single Dropped Message

1. Resolve the cause first. A policy endpoint must return PASS for the message before replay can succeed. Confirm that the source event remains valid and the message has not already been attested through another path.
2. Point the CLI at the affected member's database and find the full message IDs:

   ```bash
   verifier ccv job-queue list --queue task-verifier \
     --message-id 0x<FULL_ID_1>,0x<FULL_ID_2> --output json --limit 0
   ```

   Filters run before the per-queue limit. Omit the queue to search both queues and omit the owner to search every owner in this database. Repeated `--message-id` flags are also supported. JSON preserves complete diagnostic text, IDs, archive/retry times and decimal-string selectors.
3. Restore the selected job:

   ```bash
   verifier ccv job-queue reschedule --queue task-verifier --message-id 0x<FULL_ID>
   ```

   With one matching owner/job the CLI infers and prints the owner. Multiple owners require an explicit `--verifier-id` from the reported list. Multiple failed jobs for that owner/message require `--job-id <UUID>`. An explicit wrong owner fails; it never falls back. `--retry-duration` defaults to 1h and must be positive.
4. The running queue normally picks up the restored pending job within about 30 seconds. A matching active job or concurrent restore causes a safe error with the archive intact. A repeat after a successful restore reports that no matching failed archive row remains. Selection, removal and insertion share a transaction.
5. Confirm that the specific message ID reaches the aggregator/indexer. Queue admission or `storage_write/succeeded` metrics alone cannot identify the message. Failed archive rows left by earlier attempts are not reconciled against later attestations.

See the [job-queue command reference](../../cli/jobqueue/README.md) and [policy hook guidance](../../verifier/docs/policy_hook.md).

<a id="4-rewind-the-checkpoint-for-a-range"></a>

## 4. Recover a Source Range

### Establish the scope

Identify each affected owner/node and source chain, then query retained evidence:

```bash
verifier ccv recovery events --verifier-id <OWNER> --chain-selector <SOURCE> \
  --since 2026-09-01T00:00:00Z --until 2026-09-10T00:00:00Z --limit 100
```

Filter by full message IDs, destination selector, source block range or reason as needed. Follow `next_cursor` with `--before-id` using the same filters. Reasons are `remote_chain_cursed`, `message_disablement_rule`, `finality_violation`, and `operator_reset`.

Known drops carry message IDs, block numbers and optional reader-provided transaction/block hashes. A finality incident separately records detection-height/hash evidence and pending/sent tracking counts, and links known pending messages by incident ID. A flush never deletes previously published jobs or undoes attestations. The rules checker does not currently expose a rule ID.

Read coverage metadata on every query. History starts at upgrade; disabled intervals, downtime, failed audit writes and expired data leave gaps. Unknown curse/rule state and ordinary confirmation waiting are not recorded as confirmed drops. Empty history cannot establish that no messages were affected. Use canonical source events, logs and traces to cover missing intervals.

Corroborate a finality block with `verifier_source_reader_state{state="finality_blocked"}` or `verifier_source_chain_finality_violated`, and logs `FINALITY VIOLATION DETECTED - block hash changed` / `parent hash mismatch`. Disabled readers now remain present for recovery control, including after startup; their registry state and history distinguish current health from past evidence.

For a finality incident, compare stored/observed hashes with canonical RPC headers to establish a known-good common boundary. The first detected mismatch may be later than the earliest affected block. Include pending messages and messages emitted while the reader was disabled. A disabled checkpoint of zero is not evidence of the fork boundary.

### Submit live recovery

Clear the curse/rule or other root cause and allow refreshed state to reach the verifier. Choose the inclusive first and last affected blocks. Source recovery covers all applicable lanes in that source range.

```bash
verifier ccv recovery replay --verifier-id <OWNER> --chain-selector <SOURCE> \
  --from-block <FIRST> --to-block <LAST> --actor <OPERATOR> --note '<INCIDENT_AND_REASON>'
```

Omit `--to-block` only when a fixed copy of the reader's recently advertised head is appropriate. The returned `to_block` is captured at submission and never follows later heads. Missing/stale head observations require an explicit upper bound. Keep the returned operation ID; supplying your own `--request-id <UUID>` lets a disconnected caller safely repeat submission.

A disabled reader requires an explicit investigated reset instead:

```bash
verifier ccv recovery reset-reader --verifier-id <OWNER> --chain-selector <SOURCE> \
  --from-block <FIRST> --to-block <LAST> --actor <OPERATOR> \
  --note '<INCIDENT; EVIDENCE_FOR_KNOWN_GOOD_BOUNDARY>'
```

The reset boundary is `FIRST - 1` (zero for a range beginning at zero). This is an operator decision about canonical history. The live reset coordinates the database, buffered checkpoints and in-memory checker, records the action, and works for readers disabled at startup. An ordinary replay never clears disablement. A new finality violation remains sticky and requires a new investigated reset; resuming an old applied reset cannot clear it.

### Observe completion and control work

```bash
verifier ccv recovery status --operation-id <UUID>
verifier ccv recovery list --verifier-id <OWNER> --chain-selector <SOURCE>
verifier ccv recovery cancel --operation-id <UUID>
verifier ccv recovery resume --operation-id <UUID>
```

Inspect state, fixed target, next block, admission/drop/conflict/filter/error counts and `last_error`. Waiting for finality, known admission state, a future head or queue capacity leaves the cursor unchanged. RPC/storage failures roll back a chunk and report `failed`; resolve the cause before resume. Requests survive restart at their last committed block. Cancellation waits for an in-flight transaction and leaves committed work intact.

Ordinary replay leaves the normal checkpoint alone and normal traffic continues. An applied reset holds normal polling until its range completes; cancelling/failing that reset intentionally keeps the durable pause. Resume that operation to finish. A superseding investigated reset is needed after another finality violation. Do not try to release the pause by editing checkpoint rows.

Each recovery poll is bounded to at most 100 source blocks, 1,000 returned events and the configured source RPC timeout, with one chunk per owner at a time in the process and an active verification-queue capacity guard. Overlapping ranges cannot duplicate active jobs. Messages already attested can be reverified and old failed archives remain. `completed` means the range's queue work and evidence committed; confirm the affected IDs' final results separately.

### Legacy offline checkpoint fallback

Use for a deployment without this recovery capability, including a Chainlink core binary that has not wired in the commands. It is not a substitute for controlling an unfinished applied live reset.

1. Stop the node. Existing CL commands require the node database lease; neither offline checkpoint editing nor `enable` coordinates an already running reader.
2. Set `N` to one block before the first block to recover, and no later than the investigated common boundary after a finality violation:

   ```bash
   verifier ccv chain-statuses set-finalized-height \
     --chain-selector <SOURCE> --verifier-id <OWNER> --block-height <N>
   ```

   In CL mode use `chainlink node ccv chain-statuses set-finalized-height` with the same flags. The next start reads `N + 1`; this legacy path has no fixed end height.
3. If disabled, also run `ccv chain-statuses enable` for the same owner/source while stopped, then verify both fields with `ccv chain-statuses list`. Enabling a zero checkpoint alone unintentionally starts at block 1.
4. Start the node. Confirm its logged start block, reader progress and the affected message IDs' results. Restart initializes a fresh checker and cannot recover its prior hash history or undo results.

See the [live recovery reference](../../cli/recovery/README.md) and [chain-status command reference](../../cli/chainstatuses/README.md).

## 5. Block or Unblock a Class of Traffic

Use [aggregator message-disablement rules](../../aggregator/cli/messagedisablement/README.md) for a chain, lane or token. Allow both aggregator and verifier refresh intervals after deleting a rule. Removing a rule does not re-admit messages already dropped: recover the affected source range with step 4.

## 6. Deployment and Coverage Limits

The new recovery/job-queue commands are exposed by the standalone verifier. Wiring them into Chainlink core, cross-node fan-out, indexer engine changes and an admin UI are outside this change. Owner inference is local to one selected archive queue/database; source recovery always requires an explicit owner. There is no per-message policy bypass. Keep canonical-chain investigation and final-result verification in the operator workflow.
