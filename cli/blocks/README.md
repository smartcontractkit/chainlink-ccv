# CCV blocks CLI

The standalone verifier's version of the Chainlink node's `find-lca` and `remove-blocks` commands. They work on the LogPoller's stored blocks and logs (`evm.log_poller_blocks`, `evm.logs`) when the verifier reads EVM chains through the LogPoller (`log_poller_enabled = true` in the EVM config).

## Commands

| Command | Description |
|---------|-------------|
| `find-lca` | Prints the highest stored block whose hash the chain RPC also has, in the node's format: a "Last Common Ancestor" title, then ChainID, Block Hash and Block Number as a list. Only reads, so it works with the verifier running or stopped. |
| `remove-blocks` | Deletes the chain's `evm.logs` and `evm.log_poller_blocks` rows with block number `>= --start` (inclusive). **The verifier must be stopped.** |

Both take `--evm-chain-id`, as on the node. Neither takes a verifier ID: the LogPoller tables are scoped by EVM chain ID. The chain ID is mapped to its chain selector with chain-selectors, so an unknown chain ID is rejected.

`remove-blocks` also takes `--start`, the first block to delete, a positive number. Use one more than the block `find-lca` prints, so only data that left the chain is deleted. Retention is not checked: deleting data older than the filter retention cannot be re-indexed cheaply.

`remove-blocks` asks for no confirmation and prints nothing but a log line, as on the node.

## Usage

```bash
verifier ccv blocks find-lca --evm-chain-id <chain id>
verifier ccv blocks remove-blocks --evm-chain-id <chain id> --start <lca+1>
```

## What it reads

| Needs | From |
|-------|------|
| The LogPoller switch | `log_poller_enabled` in the mounted EVM config (`EVM_CONFIG_PATH`, default `/etc/evm/config.toml`) |
| The chain's RPC (`find-lca` only) | The mounted EVM config (`EVM_CONFIG_PATH`, default `/etc/evm/config.toml`) |
| The database | `[db].url` in the EVM secrets file (`EVM_SECRETS_PATH`, default `/etc/evm/secrets.toml`) |

The commands check the switch and the chain before they open the database, and open it without running migrations. They exit non-zero and change nothing when the switch is off (the chain reads through the RPC source reader), the chain ID is not a known EVM chain, or its chain is missing from the EVM config (`find-lca`), or the `evm` schema is missing. `--help` needs none of this.

The token verifier binary has the same commands and fails with a message that it has no LogPoller.

## Operator note

These commands are one step of the finality violation runbook, [Resolving a Finality Violation](../../docs/runbooks/resolving-finality-violation.md).
