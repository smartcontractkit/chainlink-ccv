# Migration tooling: JD-sourced expected_id check, effective-config diff, block-time fallback warning

## Executive Summary

- `ccv migrate export` gains an optional `--expected-id` flag carrying the operator's signing
  address as Chainlink Labs reads it from JD (`OnchainSigningAddress`). The export now fails when
  the decoded key does not carry it — closing the hole where choosing the wrong OCR2 bundle still
  produced a self-consistent `[key_import]` snippet.
- New `ccv migrate inspect-config --config <path>` subcommand prints the conversion warnings and
  each chain's effective standalone settings (finality, TXM block time, head-tracker persistence,
  RPC node set) by running the same config load and chainlink-evm defaulting the runtime uses.
  This is the documented way to run the pre-cutover per-chain settings diff.
- The TXM v2 block-time fallback (2s when nothing explicit is configured) is now logged at warn
  per chain at startup instead of applying silently.
- No behavior changes to running deployments; all three changes surface in migration tooling and
  startup logs only.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `migration.ExportConfig.ExpectedID` | added | `ExpectedID` | `migration/export.go` | [JD-sourced expected_id](#jd-sourced-expected_id) |
| `migration.checkExpectedID` | added | `checkExpectedID` | `migration/export.go` | [JD-sourced expected_id](#jd-sourced-expected_id) |
| `ccv migrate inspect-config` | added | `inspect-config` | `cli/migrate/inspect_config.go` | [Effective-config diff tooling](#effective-config-diff-tooling) |
| `evm.LoadConfigFile` | added | `LoadConfigFile` | `integration/pkg/accessors/evm/factory_constructor.go` | [Effective-config diff tooling](#effective-config-diff-tooling) |
| `evm.EffectiveChainConfigs` | added | `EffectiveChainConfigs` | `integration/pkg/accessors/evm/effective_config.go` | [Effective-config diff tooling](#effective-config-diff-tooling) |
| `evm.buildChainlinkEVMTOML` | refactor | `buildChainlinkEVMTOML` | `integration/pkg/accessors/evm/chainlink_config.go` | [Effective-config diff tooling](#effective-config-diff-tooling) |
| `evm.newMultiNodeClientFromInfo` | behavior-changed | `txm_block_time` | `integration/pkg/accessors/evm/multi_node_client.go` | [Block-time fallback warning](#block-time-fallback-warning) |

## Breaking Changes

No breaking changes. `ExpectedID` is optional; exports without it behave exactly as before.
`newChainlinkEVMConfig` keeps its signature and behavior — the TOML construction was extracted
into `buildChainlinkEVMTOML` unchanged, so the report tooling reads what the runtime builds.

## Behavior Changes

### JD-sourced expected_id

`ccv migrate export` self-checks the exported bundle by decoding it, but that check is
self-referential: any bundle decodes to a self-consistent identity, so picking the wrong OCR2
bundle produced a valid-looking `[key_import]` snippet. The operator can now pass
`--expected-id`, the signing address Chainlink Labs hands over from the operator's JD record;
a mismatch fails the export while the node is still up, with an error naming the wrong-bundle
cause. A malformed flag value fails before comparison. The check composes with the existing
boot-time one: `[key_import].expected_id` still guards against mounting the wrong file, and the
flag guards against choosing the wrong key in the first place.

### Effective-config diff tooling

The node-config conversion previously existed only inside the accessor factory; its result was
never inspectable beyond the startup warnings. `ccv migrate inspect-config` accepts either the
node's TOML or a standalone-format EVM config, loads it through the exported `LoadConfigFile`
(the same path the runtime uses), and prints a JSON report: `converted_from_node_config`, the
conversion's dropped-setting warnings, and per chain the effective settings projected by the new
`EffectiveChainConfigs` — which runs each chain through the same `buildChainlinkEVMTOML` the
runtime adapter uses, so the report cannot drift from what the process will run. RPC URLs are
deliberately excluded from the report (they can carry API keys); node names, order, and
WebSocket coverage carry the redundancy picture. `txm_block_time_is_default: true` flags chains
running the 2s fallback. `--chain-selector` filters to one chain. The command needs no database,
no secrets, and no network, like the other `ccv migrate` subcommands. The migration procedure's
step 3 now ends with this diff as the recorded pre-cutover settings review.

### Block-time fallback warning

`newMultiNodeClientFromInfo` warns when a chain has no configured TXM block time and the 2s
fallback applies, naming the chain and pointing at `txm_block_time` /
`Transactions.TransactionManagerV2.BlockTime`. The fallback itself is unchanged; a missed
per-chain value is now loud at startup instead of only visible in retry behavior.

## Compatibility & Requirements

- No dependency, schema, or config changes; the main module still imports no JD/grpc packages —
  the JD value arrives out-of-band as a flag, which also works for operators without JD access.
- `ccv migrate inspect-config` links the EVM accessor package into the CLI surface; the verifier
  binary already imports it for accessor registration, so binary dependency graphs are unchanged.

## References

- Tracker: `cutover-tickets.md` items F6, A3, A2.
- Migration procedure: `docs/migration/evm-cl-to-standalone.md` (steps 2 and 3, "Why the node's
  TOML is reused as-is").
- Prior entries: `2026-08-13_cutover_parity_followups.md`, `2026-08-14_rmn_address_onchain_derivation.md`.
