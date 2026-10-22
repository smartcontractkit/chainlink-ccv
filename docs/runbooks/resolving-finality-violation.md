# Runbook: Resolving a Finality Violation (Log Poller)

## Scenario

A chain's source reader reports a finality violation: the log poller found that a block it had
already saved as finalized no longer matches the chain. The verifier disables the chain
(`disabled = true` and `finalized_block_height = 0` in `ccv_chain_statuses`), logs `FINALITY VIOLATION DETECTED`, and stops
verifying that source until an operator resolves it.

This runbook applies to committee verifiers that read through the log poller
(`Feature.LogPoller = true`), whether they run inside a Chainlink node or as a standalone verifier.
The steps are the same on both. Only the command prefix differs:

| | Chainlink node | Standalone verifier |
|---|---|---|
| Find the last common ancestor | `chainlink blocks find-lca` | `verifier ccv blocks find-lca` |
| Remove blocks | `chainlink node remove-blocks` | `verifier ccv blocks remove-blocks` |
| Chain statuses | `chainlink node ccv chain-statuses` | `verifier ccv chain-statuses` |

Do not use `ccv recovery reset-reader` or `replay` for this case on a log poller chain. A reset
resumes without repairing the stored blocks above the last common ancestor, so the reader reads
stale blocks or reports the violation again.

## Placeholders

- `<evm-chain-id>`: the EVM chain ID of the affected source chain.
- `<chain-selector>`: its chain selector.
- `<verifier-id>`: the verifier ID (see `chain-statuses list`).
- `L`: the last common ancestor block number found in step 2.

## Standalone verifier environment

The standalone commands run in the verifier's container or host, not inside a node:

- Database: the verifier secrets file (`[db].url`), or `CL_DATABASE_URL`.
- `find-lca` needs the chain's RPC from the mounted EVM config (`EVM_CONFIG_PATH`, default `/etc/evm/config.toml`).
- The commands read `[Feature] LogPoller` from the bootstrap config (`BOOTSTRAPPER_CONFIG_PATH`, default `/etc/config.toml`)
  and refuse to run when it is off.

On a node the commands use the node's own configuration and take the node's database lock. A
standalone verifier has no such lock, so nothing but this runbook keeps the verifier stopped while
you run steps 4 to 6.

## 1. Confirm the violation

- The chain shows `disabled = true`:

  ```bash
  # node
  chainlink node ccv chain-statuses list
  # standalone
  verifier ccv chain-statuses list
  ```

- The logs contain `FINALITY VIOLATION DETECTED`.

## 2. Find the last common ancestor

`find-lca` only reads, so run it with the node or verifier running:

```bash
# node
chainlink blocks find-lca --evm-chain-id <evm-chain-id>
# standalone
verifier ccv blocks find-lca --evm-chain-id <evm-chain-id>
```

Record the block number as `L`. It is the highest block whose hash in the log poller database
matches the chain.

## 3. Stop the node or verifier

`remove-blocks` takes the node's database lock on a node. On both paths a running verifier can
overwrite the checkpoint and the log poller stores blocks again as soon as it is deleted.

## 4. Remove the blocks above the LCA

`--start` is inclusive, so pass `L+1` to keep block `L`:

```bash
# node
chainlink node remove-blocks --start <L+1> --evm-chain-id <evm-chain-id>
# standalone
verifier ccv blocks remove-blocks --evm-chain-id <evm-chain-id> --start <L+1>
```

This removes the log poller's blocks and logs from `L+1` upward for the chain. Other log poller
consumers on the chain lose those logs too; the log poller refetches them as it catches up.

Never pass a start below `L+1`. The command does not check retention, and `L+1` from `find-lca`
is always inside the stored data, so only data that left the chain is deleted. Older data cannot
be re-indexed cheaply.

## 5. Reset the verifier checkpoint to the LCA

Set the checkpoint to `L` itself, not `L+1`. The verifier resumes at `finalized_block_height + 1`.

```bash
# node
chainlink node ccv chain-statuses set-finalized-height \
  --chain-selector <chain-selector> --verifier-id <verifier-id> --block-height <L>
chainlink node ccv chain-statuses list
# standalone
verifier ccv chain-statuses set-finalized-height \
  --chain-selector <chain-selector> --verifier-id <verifier-id> --block-height <L>
verifier ccv chain-statuses list
```

Confirm `finalized_block_height` reads `L`. Skipping this step leaves the checkpoint above the
LCA, and the verifier would skip messages emitted on the new fork between `L+1` and the old
checkpoint.

## 6. Re-enable the chain and start

Run `enable` while the node or verifier is still stopped, then start it. Run `set-finalized-height`
the same way: the commands change the stored row, and the running service reads it only at start.

```bash
# node
chainlink node ccv chain-statuses enable --chain-selector <chain-selector> --verifier-id <verifier-id>
# standalone
verifier ccv chain-statuses enable --chain-selector <chain-selector> --verifier-id <verifier-id>
```

On start the verifier registers the log poller filter, anchors the log poller at the checkpoint
if it is empty, and replays from `L+1`. The chain reports not ready until the replay finishes.

## 7. Verify

- The chain is enabled and healthy, and the checkpoint advances past `L`.
- The logs contain no new `FINALITY VIOLATION DETECTED`.
- Messages sent after the fork are verified.

## Caveats

- If a violation is reported again right after the restart, the log poller still holds blocks
  that disagree with the chain. The chain is disabled again. Repeat from step 2. This is also what
  happens when step 4 was skipped.
