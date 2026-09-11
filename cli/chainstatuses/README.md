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

Shut down the node or verifier before running `enable`, `disable`, or `set-finalized-height`. Changes take effect on the next start.
