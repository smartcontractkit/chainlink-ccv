# CCV chain-statuses CLI

CLI commands to inspect and mutate chain status rows in the `ccv_chain_statuses` table (chain selector, verifier ID, finalized block height, disabled flag).

## Commands

| Command                | Description                                                                                                                                                                        |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `list`                 | List all chain status rows (table: Chain, Chain Selector, verifier_id, finalized_block_height, disabled, updated_at).                                                              |
| `enable`               | Set `disabled = false` for a given chain and verifier.                                                                                                                             |
| `disable`              | Set `disabled = true` for a given chain and verifier.                                                                                                                              |
| `set-finalized-height` | Set `finalized_block_height` for a given chain and verifier, and rewind the LogPoller when the verifier uses it (see below). Deep rewinds also disable the chain pending a replay. |

`enable`, `disable`, and `set-finalized-height` require:

- `--chain-selector` – chain selector (e.g. from [chain-selectors](https://github.com/smartcontractkit/chain-selectors))
- `--verifier-id` – verifier ID

`set-finalized-height` also requires:

- `--block-height` – finalized block height to set

## Usage

**Chainlink node**

```bash
chainlink node ccv chain-statuses list
chainlink node ccv chain-statuses disable --chain-selector <selector> --verifier-id <id>
chainlink node ccv chain-statuses enable --chain-selector <selector> --verifier-id <id>
chainlink node ccv chain-statuses set-finalized-height --chain-selector <selector> --verifier-id <id> --block-height <height>
```

**Standalone verifier**

Set `CL_DATABASE_URL` to the verifier’s PostgreSQL connection string, then:

```bash
verifier ccv chain-statuses list
verifier ccv chain-statuses disable --chain-selector <selector> --verifier-id <id>
# etc.
```

## LogPoller rewind

When the verifier's source reader is backed by the LogPoller, the LogPoller resumes from its own newest stored block on restart, not from `finalized_block_height`. Lowering the height alone would therefore not re-read the logs in between. `set-finalized-height` handles this by deleting the LogPoller's stored blocks and logs from `block-height + 1` onward, in the same database transaction as the height update, so both commit or roll back together. The source reader then resumes at `block-height + 1`. The LogPoller resumes after its newest remaining stored block, which may be below `block-height + 1`: it stores blocks sparsely (backfill saves only the last block of each batch), so there may be no stored block exactly at `block-height`. Re-reading those earlier blocks is harmless because log inserts are idempotent.

The rewind only runs when the database shows the verifier uses the LogPoller on that chain: the `evm.log_poller_filters` table exists and has a filter for the chain named `<verifier-id> - <on-ramp address>`.

Deployments are assumed to run one CCV verifier per node, so this verifier is the only CCV reader of the chain in that node.

| Situation                                                                 | Result                                                                                                                                                            |
| ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LogPoller has blocks above `block-height` and at least one at or below it | Height set; LogPoller blocks and logs from `block-height + 1` deleted; the message reports the deleted range and that the verifier resumes at `block-height + 1`. |
| LogPoller has no blocks above `block-height`                              | Height set; nothing to rewind.                                                                                                                                    |
| LogPoller has no blocks for the chain, or all are above `block-height`    | Height set; LogPoller blocks and logs from `block-height + 1` deleted; chain **disabled**; a replay runbook is printed (see below).                               |
| LogPoller tables are absent or no matching filter exists                  | Height set; rewind skipped with a message.                                                                                                                        |
| Chain is not EVM, or its family is unknown                                | Height set; rewind skipped with a message.                                                                                                                        |

### Deep rewinds: replay, then re-enable

With no stored block at or below `block-height`, the LogPoller cannot resume at `block-height + 1` on its own: it would treat the chain as new and start at the current finalized block, skipping the gap. This happens when the target is older than the LogPoller's pruning window (`LogKeepBlocksDepth`) or the LogPoller has no blocks yet. The command then disables the chain in the same transaction, so the verifier does not read the gap before it is filled, and prints these steps with the real values filled in:

1. Start the node and wait for the LogPoller's first poll on the chain.
2. Run `chainlink blocks replay --family evm --chain-id <chain-id> --block-number <block-height + 1>`. If it reports that there are no saved blocks yet, wait for the next poll and run it again. If it rejects the block as above the chain's latest block, there is no gap to refill; skip to step 4.
3. Wait for the node logs to show that the replay has finished.
4. Stop the node.
5. Run `chainlink node ccv chain-statuses enable --chain-selector <selector> --verifier-id <id>`.
6. Start the node.

The source reader's LogPoller filter keeps logs for 30 days. Logs older than that may be pruned again before the verifier reads them, so a rewind further back than the retention window may not be recoverable this way.

## Operator note

Shut down the node or verifier before running `enable`, `disable`, or `set-finalized-height`. Changes take effect on the next start. These commands remain the offline fallback for deployments without live recovery.

Upgraded standalone verifiers support [durable live source recovery](../recovery/README.md), including an explicit investigated `reset-reader` for disabled readers. Use that workflow while the service is running so buffered checkpoints and the reader lifecycle are coordinated. Editing a chain-status row alone cannot safely reset a live reader. An unfinished applied live reset must be resumed through its recovery operation; changing only the checkpoint does not release its durable polling pause.
