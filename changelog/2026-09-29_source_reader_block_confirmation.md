# Source reader confirms the source block before it publishes a task

## Executive Summary

- The source reader keeps the block number, block hash, and transaction hash of each pending task equal to the most recent scan result.
- A task becomes ready only when the most recent successful scan covered its block.
- Before a task goes to the task queue, the source reader compares its block hash with the canonical header at the same height.
- The check uses the existing `vtypes.VerificationTask.SourceBlockHash`, which the source reader copies from `protocol.MessageSentEvent.BlockHash`. No fields are added.
- No breaking changes. A task with an empty `SourceBlockHash` keeps its current behavior.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `sourcereader.Service` readiness | behavior-changed | `sourcereader\.NewService\(` | `verifier/pkg/sourcereader/service.go:796` | [#readiness-rules](#readiness-rules) |
| `sourcereader.Service.addToPendingQueueHandleReorg` | behavior-changed | `addToPendingQueueHandleReorg\(` | `verifier/pkg/sourcereader/service.go:596` | [#pending-task-update](#pending-task-update) |
| `vtypes.VerificationTask.SourceBlockHash` | behavior-changed | `\bSourceBlockHash\b` | `verifier/pkg/vtypes/types.go:17` | [#source-block-hash](#source-block-hash) |
| `monitoring.EventReorgMovedPending` | added | `\bEventReorgMovedPending\b` | `verifier/pkg/monitoring/tracing.go:11` | [#tracing-event](#tracing-event) |

## Breaking Changes

*No breaking changes.*

## Readiness rules

`sourcereader.Service.sendReadyMessages` applies these rules to each pending task, in this order.

1. The task block must be at or below `scannedThrough`, the highest block that the most recent scan covered. `processEventCycle` sets the value:

   | Scan result | `scannedThrough` |
   |---|---|
   | All ranges succeed | The latest block |
   | Some ranges succeed, then a range fails | The end of the last range that succeeded |
   | The first range fails | The block before the scan start |

   A task above this limit stays pending until a later scan covers it. If the task is at or below the checkpoint, the checkpoint does not advance in this cycle.
2. `admission` runs the curse, message-disablement, and finality checks, the same as before.
3. `confirmBlockHashesLocked` (`verifier/pkg/sourcereader/service.go:725`) gets the headers for the ready tasks that have a `SourceBlockHash`, with one `SourceReader.GetBlocksHeaders` call:

   | Result | Task |
   |---|---|
   | The canonical hash is the same as `SourceBlockHash` | Published |
   | The canonical hash is different | Stays pending. `ReorgTracker` records the sequence number. The scan cursor moves to the block before the task, and the checkpoint does not advance in this cycle. The next scan finds the message in its current block, or removes the task. |
   | The header is missing, or the call returns an error | Stays pending. The checkpoint does not advance in this cycle. An error makes all hashed tasks in the call wait, also when the call returns some headers. |
   | `SourceBlockHash` is empty | Published with no header request |

Tasks that do not pass steps 1 and 2 do not cause a header request. Source recovery (`recoverRange`) does not use these steps and is unchanged.

## Pending task update

When a scan returns a message ID that is already pending, and its block number, block hash, or transaction hash is different, the pending task takes the new observation. The task keeps its trace context. `ReorgTracker` records the sequence number, so a custom-finality message waits for full finality. For a task that was already sent, the source reader updates only the stored block number and block hash. It does not remove the task from the queue.

Pending-task removal after a reorg is now in one helper, `removeReorgedPendingLocked`. The log message and the tracing event are the same as before.

## Source block hash

`vtypes.VerificationTask.SourceBlockHash` was optional reader metadata. Now the live readiness path also uses it to confirm the source block (see [#readiness-rules](#readiness-rules)). The field, its JSON tag, and how readers fill it do not change.

To use the block hash check with a different `chainaccess.SourceReader`:

1. Set `MessageSentEvent.BlockHash` in `FetchMessageSentEvents`.
2. Make sure that `GetBlocksHeaders` returns `BlockHeader.Hash` for the same block numbers.

## Tracing event

`monitoring.EventReorgMovedPending` (`"reorg_moved_pending"`) is added to the task span when a pending task takes a new block. The attribute `tracing.BlockNumberKey` holds the new block number.

## Compatibility & Requirements

- **Other chain families:** readers that leave `MessageSentEvent.BlockHash` empty do not get the block hash check. The scan-coverage rule and the pending-task update apply to all readers.
