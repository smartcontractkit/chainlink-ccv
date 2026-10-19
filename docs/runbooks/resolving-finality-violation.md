# Runbook: Resolving a Finality Violation (Log Poller)

## Scenario

A chain's source reader reports a finality violation: the log poller found that a block it had
already saved as finalized no longer matches the chain. The verifier disables the chain
(`disabled = true` and `finalized_block_height = 0` in `ccv_chain_statuses`), logs `FINALITY VIOLATION DETECTED`, and stops
verifying that source until an operator resolves it.

The verifier no longer deletes log poller data on startup. It only replays from its checkpoint
(`finalized_block_height + 1`), so a violation persists across restarts until the stale blocks are
removed and the checkpoint is moved back.

This runbook applies to committee verifiers running inside a Chainlink node with the log poller
enabled (`Feature.LogPoller = true`). Standalone verifiers can use the live
[recovery workflow](../../cli/recovery/README.md) instead.

## Placeholders

- `<evm-chain-id>`: the EVM chain ID of the affected source chain.
- `<chain-selector>`: its chain selector.
- `<verifier-id>`: the verifier ID (see `chain-statuses list`).
- `L`: the last common ancestor block number found in step 2.

## 1. Confirm the violation

- The chain shows `disabled = true`:

  ```bash
  chainlink node ccv chain-statuses list
  ```

- The node logs contain `FINALITY VIOLATION DETECTED`.

## 2. Find the last common ancestor

With the node running:

```bash
chainlink blocks find-lca --evm-chain-id <evm-chain-id>
```

Record the block number as `L`. It is the highest block whose hash in the log poller database
matches the chain.

## 3. Stop the node

`remove-blocks` and `set-finalized-height` take the node's database lock, and a running verifier
can overwrite the checkpoint.

## 4. Remove the blocks above the LCA

`--start` is inclusive, so pass `L+1` to keep block `L`:

```bash
chainlink node remove-blocks --start <L+1> --evm-chain-id <evm-chain-id>
```

This removes the log poller's blocks and logs from `L+1` upward for the chain. Other log poller
consumers on the chain lose those logs too; the log poller refetches them as it catches up.

## 5. Reset the verifier checkpoint to the LCA

Set the checkpoint to `L` itself, not `L+1`. The verifier resumes at `finalized_block_height + 1`.

```bash
chainlink node ccv chain-statuses set-finalized-height \
  --chain-selector <chain-selector> --verifier-id <verifier-id> --block-height <L>
chainlink node ccv chain-statuses list
```

Confirm `finalized_block_height` reads `L`. Skipping this step leaves the checkpoint above the
LCA, and the verifier would skip messages emitted on the new fork between `L+1` and the old
checkpoint.

## 6. Start the node and re-enable the chain

```bash
chainlink node ccv chain-statuses enable --chain-selector <chain-selector> --verifier-id <verifier-id>
```

Run `enable` while the node is stopped, then start it. On start the verifier registers the log
poller filter, anchors the log poller at the checkpoint if it is empty, and replays from `L+1`.
The chain reports not ready until the replay finishes.

## 7. Verify

- The chain is enabled and healthy, and the checkpoint advances past `L`.
- The logs contain no new `FINALITY VIOLATION DETECTED`.
- Messages sent after the fork are verified.

## Caveats

- Messages the verifier signed from the orphaned fork above `L` are not undone by this procedure.
  Review them separately.
- If a violation is reported again right after the restart, the log poller still holds blocks
  that disagree with the chain. Repeat from step 2.
