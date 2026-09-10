# CCV live recovery CLI

The standalone verifier accepts durable recovery requests through its existing PostgreSQL database. The running source reader performs the work on its event loop. There is no admin HTTP endpoint or UI in this change. These commands require a binary and schema containing migrations 00009 and 00010; the existing verifier migration mechanism applies them during upgrade. Chainlink core must separately expose this command group before it is available through `chainlink node`.

## Submit and control a range

```bash
verifier ccv recovery replay --verifier-id <OWNER> --chain-selector <SOURCE> \
  --from-block 1200 --to-block 1300 --actor <OPERATOR> --note 'Rule cleared; recover incident range'
verifier ccv recovery list --verifier-id <OWNER> --chain-selector <SOURCE> --limit 50
verifier ccv recovery status --operation-id <UUID>
verifier ccv recovery cancel --operation-id <UUID>
verifier ccv recovery resume --operation-id <UUID>
```

`from-block` and `to-block` are inclusive, unsigned decimal source heights; zero is supported. The maximum supported height is 18446744073709551614, leaving room for the next-block cursor. Every submission requires one explicit owner, source chain, actor and note. The owner/source must have registered a reader in this database.

Omitting `--to-block` captures the reader's advertised latest head **at submission**. That observation must be less than a minute old. Readers advertise every 30 seconds, including disabled readers that can reach their RPC. A missing or stale head requires an explicit upper bound. The target does not advance with the chain. Inspect the returned `to_block` when exact incident boundaries matter; an explicit target can wait for a future source head.

An optional `--request-id <UUID>` is an idempotency key. Repeating the same request returns its original operation and target, even after the head moves. Reusing the key for different parameters fails. A new ID creates a separate operation, including for an overlapping range.

All commands write JSON to stdout and diagnostics to stderr. Operations include their durable ID, owner/source, mode, actor/note, target, next block, state, timestamps, `reset_applied`, counters and latest error. Selectors, block heights and counters are decimal strings to preserve integer precision in browser clients.

| State | Meaning and action |
| --- | --- |
| `accepted` | Persisted and waiting for its reader's turn. |
| `running` | Processing chunks, or waiting for a source head, admission certainty, finality or queue capacity. Inspect `last_error`. |
| `completed` | The full range was scanned and its queue admissions/drop evidence committed. Verify final attestations separately. |
| `cancelled` | No further chunks run. Already committed work remains. Resume continues at `next_block`. |
| `failed` | A chunk or reset failed; its uncommitted jobs/evidence/progress rolled back. Resolve `last_error`, then resume. |
| `blocked` | The reader is disabled or a reset was superseded. Ordinary resume does not clear a finality block. |

Cancellation waits for a currently executing chunk transaction; once the command returns, further work for that request is stopped. Repeated cancel/resume is safe while applicable. Completed operations cannot resume. A process failure leaves the last committed next-block cursor; the same operation resumes when its configured reader starts again.

Counters describe this operation's attempts: `admitted` counts actual task insertions, `conflicts` counts ready tasks already in the active queue, `dropped` counts confirmed admission drops, and `filtered` counts source events excluded by the ordinary event filter/ID validation. `errors` counts failed attempts and admission-state read errors; `last_error` is the latest diagnostic. Repeated observations can contribute to several operations; these are not unique affected-message totals.

## Reader safety and load

Recovery re-reads source events through the chain-neutral reader interface and applies the same event filter, message-ID validation, curse check, disablement rules and finality requirements as normal polling. Metadata such as transaction and block hashes comes from readers. Admission publishes normal verification tasks, so normal verification and policy processing still apply. No policy or chain-specific bypass is introduced.

Only one recovery chunk per owner runs at a time in a process, and a database advisory lock serializes operations per owner/source across workers. Each poll attempts at most one chunk of at most 100 blocks (also limited by the source's configured `MaxBlockRange`), with a maximum of 1,000 returned events. A larger response fails with an instruction to choose a smaller range. RPC work uses the source poll timeout. Recovery waits at 10,000 active verification jobs for that owner; committed normal traffic runs first for ordinary replay. These bounds constrain added work, not the normal reader's existing scan behavior.

Jobs, drop evidence, counters and progress commit together. Unknown curse/rule state and ordinary finality waiting do not create drop history or advance the chunk. Active queue uniqueness prevents duplicate active jobs; an already completed or attested message can be verified again. A range covers all applicable lanes on that source, and failed archive rows remain until rescheduled or expired.

Ordinary replay never rewinds the normal reader's checkpoint. Normal polling can continue independently. Overlapping scans reconcile pending/sent tracking after a committed chunk. Deployments retain the existing requirement that one live source-reader owner controls normal polling for a given owner/source; recovery locking does not turn normal polling into a multi-writer service.

## Investigated finality reset

First establish the canonical chain and a known-good boundary. A detection height is evidence, not necessarily the first affected height. Then submit a new explicit reset:

```bash
verifier ccv recovery reset-reader --verifier-id <OWNER> --chain-selector <SOURCE> \
  --from-block 1200 --to-block 1300 --actor <OPERATOR> \
  --note 'Canonical headers checked through 1199; incident reference ...'
```

This mode requires a disabled reader, including a reader disabled at startup. It records the operator and boundary, initializes a fresh finality checker at `from-block - 1` (zero when starting at zero), writes the durable boundary/enabled state and resets buffered checkpoint state as one coordinated action. The finality checker then continues canonical header checks. It cannot reconstruct pre-upgrade or pre-reset hash history.

The reset range owns normal polling until it completes. This ownership is durable: cancelling or failing an applied reset leaves normal polling paused so a normal checkpoint cannot skip unfinished recovery. Resume that operation after resolving the cause. Completion persists no checkpoint beyond current finality before releasing normal polling. A later violation disables the reader again; resuming an already applied reset cannot clear it. A **new** investigated reset is required and marks an older applied reset as superseded.

Published jobs and previous attestations are never deleted by a reader reset or by finality incident handling. Inspect their canonicality separately. There is no automatic undo of prior results.

## Query drops and incidents

```bash
verifier ccv recovery events --verifier-id <OWNER> --chain-selector <SOURCE> \
  --reason remote_chain_cursed --from-block 1200 --to-block 1300 --limit 50
verifier ccv recovery events --message-id 0x<FULL_ID_1>,0x<FULL_ID_2> \
  --since 2026-09-01T00:00:00Z --until 2026-09-10T00:00:00Z
verifier ccv recovery events --verifier-id <OWNER> --chain-selector <SOURCE> \
  --before-id <NEXT_CURSOR> --limit 50
```

Filters also include `--dest-chain-selector`; message flags can be repeated. Full message IDs use the same normalization and validation as `job-queue list`. All filters apply before keyset pagination. Results are newest event ID first, page size 1–500 (default 50). Pass `next_cursor` as `--before-id` while retaining the same filters. `since`/`until` match overlapping first/last observation windows.

Events expose owner/node, source/destination, full known message ID, source block, kind/stage/reason, observation count/times, expiry and optional transaction/block hashes. Missing metadata is null. The reason vocabulary is bounded to `remote_chain_cursed`, `message_disablement_rule`, `finality_violation`, and `operator_reset`.

A finality incident is a separate record containing detection-height/hash evidence when supplied by the checker, pending-flush and sent-tracking-flush counts, and `published_jobs_deleted: false`. Known pending messages link through the incident ID. Rule IDs are unavailable from the current boolean rules-checker interface; the history does not invent a rule reference. Unknown admission state is waiting, not a confirmed drop.

Drops deduplicate on owner/node/source/message/block/hash/transaction/reason/incident; repeated observations increment the count and extend expiry. Events expire 30 days after the last observation. Cleanup runs hourly in bounded batches of 5,000; expired evidence is excluded from queries immediately. Completed/cancelled/failed operation history is cleaned after 30 days, except an applied reset still holding normal polling. Active and blocked requests are retained.

Every page includes coverage text and reader metadata: first history time, current process session, last heartbeat, observed head, disable/reset state, and audit-failure count/time. History begins with this upgrade. It cannot enumerate traffic never observed while disabled, during downtime, or before installation; expired rows and failed audit writes also leave gaps. Audit write failure is logged and metered and never prevents a finality block. Its count is persisted at the next successful heartbeat; a process failure before that heartbeat can lose that count. Absence of evidence never proves no affected messages. Investigate canonical source events to cover those intervals.

See the [remediation runbook](../../docs/runbooks/remediating-stuck-or-dropped-messages.md) for the operational sequence and the legacy offline checkpoint fallback.
