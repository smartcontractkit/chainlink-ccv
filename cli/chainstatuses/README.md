# CCV chain-statuses CLI

CLI commands to inspect and mutate chain status rows in the `ccv_chain_statuses` table (chain selector, verifier ID, finalized block height, disabled flag).

## Commands

| Command | Description |
|---------|-------------|
| `list` | List all chain status rows (table: Chain, Chain Selector, verifier_id, finalized_block_height, disabled, updated_at). |
| `enable` | Set `disabled = false` for a given chain and verifier. |
| `disable` | Set `disabled = true` for a given chain and verifier. |
| `set-finalized-height` | Set `finalized_block_height` for a given chain and verifier. |

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

## Operator note

To reset a chain after a log poller finality violation, follow [Resolving a Finality Violation](../../docs/runbooks/resolving-finality-violation.md). Set `--block-height` to the LCA block itself, not LCA+1.

Shut down the node or verifier before running `enable`, `disable`, or `set-finalized-height`. Changes take effect on the next start. For a log poller finality violation these commands are steps 5 and 6 of the runbook, on a node and on a standalone verifier alike: run both while the service is stopped, then start it.

For a chain that uses the RPC source reader, a standalone verifier can also use [durable live source recovery](../recovery/README.md), including an explicit investigated `reset-reader` for disabled readers. Editing a chain-status row alone cannot safely reset a live reader. An unfinished applied live reset must be resumed through its recovery operation; changing only the checkpoint does not release its durable polling pause. `reset-reader` and `replay` are not the recovery for a log poller chain with a finality violation.
