# EVM chain settings carry over from the node config, over the ccip image's chain defaults

## Executive Summary

- A converted Chainlink node config's chain-level `[[EVM]]` settings now reach the standalone runtime (gas estimator, node pool, head tracker, chain type, RPC error patterns, finalized block offset, and the rest). Before, everything except finality and the TXM v2 block time was dropped with a warning.
- Chain defaults now resolve the way a Chainlink `ccip` node image resolves them: chainlink-evm's built-ins with CCIP's overrides (`ccip/config/evm` in the chainlink repo), both embedded in the binary. Before, standalone used chainlink-evm's built-ins alone, the same gap a NOP hit on the core image without `CL_CHAIN_DEFAULTS` (for example a 500,000 instead of 8,000,000 gas limit cap).
- Nothing in either path stops a process. A defaults file or key that does not load is skipped with a startup warning. A node setting this release does not know, or that its chainlink-evm rejects, is dropped by name and the chain still builds.
- `BuildChainlinkEVMTOML` no longer hands TXM v2 an AutoPurge without a `Threshold`. Scroll's chain defaults did, so the executor could not create a transaction manager for Scroll chains.
- Affects `integration/pkg/accessors/evmconfig`, the EVM accessor's startup log, and `ccv migrate inspect-config`. No Go API is removed or changed; the conversion warnings change.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evmconfig.BuildChainlinkEVMTOML` | behavior-changed | `BuildChainlinkEVMTOML\(` | `integration/pkg/accessors/evmconfig/chainlink_config.go:120` | [#node-chain-settings-carry-over](#node-chain-settings-carry-over) |
| `evmconfig.Conversion.Warnings` | behavior-changed | `dropped set chain-level settings` | `integration/pkg/accessors/evmconfig/clnode_config.go:479` | [#conversion-warnings](#conversion-warnings) |
| `ccv migrate inspect-config` report | behavior-changed | `chain_defaults` | `cli/migrate/inspect_config.go:57` | [#inspect-config-report](#inspect-config-report) |
| `evmconfig.ChainDefaultsSource` | added | `ChainDefaultsSource\(` | `integration/pkg/accessors/evmconfig/chaindefaults.go:148` | [#embedded-chain-defaults](#embedded-chain-defaults) |
| `evmconfig.ChainDefaultsProblems` | added | `ChainDefaultsProblems\(` | `integration/pkg/accessors/evmconfig/chaindefaults.go:159` | [#embedded-chain-defaults](#embedded-chain-defaults) |
| `evmconfig.ChainDefaultsDir` | added | `ChainDefaultsDir\(` | `integration/pkg/accessors/evmconfig/chaindefaults.go:142` | [#embedded-chain-defaults](#embedded-chain-defaults) |
| `just sync-chain-defaults` | added | `sync-chain-defaults` | `tools/bin/sync-chain-defaults.sh` | [#keeping-the-defaults-current](#keeping-the-defaults-current) |

## Breaking Changes

*No breaking changes.* Code that matches on conversion warning text should read
[Conversion warnings](#conversion-warnings): the "no standalone equivalent" chain-level warning is gone.

## Migration Guide

1. Operators mounting their node's TOML change nothing. Re-run `ccv migrate inspect-config`; expect fewer warnings.
2. Do not set `CL_CHAIN_DEFAULTS` on verifier or executor containers. With it set, chainlink-evm loads that directory at init instead of the embedded defaults, and exits on a file it cannot decode.
3. After bumping chainlink-evm in `go.mod`, run `just sync-chain-defaults`. To pick up new CCIP chain defaults, run `just sync-chain-defaults <chainlink branch, tag, or full commit SHA>`.

## Node chain settings carry over

`convertChainlinkNodeConfig` keeps each chain's merged `evmtoml.Chain` (minus `KeySpecific`) on the
converted `ChainConfig`, in memory only: the standalone format has no field for it. `ToInfos` copies
it to `Info`, and `BuildChainlinkEVMTOML` applies it over the chain defaults, then applies what
standalone fixes itself (`standaloneSettings`: `HeadTracker.PersistenceEnabled = false`,
`LogBroadcasterEnabled = false`, `BalanceMonitor.Enabled = false`, `Transactions.Enabled = true`,
`Transactions.ForwardersEnabled = false`, `TransactionManagerV2.Enabled = true`,
`TransactionManagerV2.DualBroadcast = false`), the finality pair, and the TXM v2 block time. An
explicit `NodePool.NewHeadsPollInterval` is now kept for HTTP-only pools; only an unset one takes
`DefaultNewHeadsPollInterval`.

If the carried settings fail chainlink-evm validation but the chain builds without them, the
conversion re-adds them one at a time and drops only those that do not build
(`buildableChainSettings`). If a value in the file does not decode into this release's types at
all, the whole-file decode used to fail; now each `[[EVM]]` block is rebuilt from the raw TOML one
setting at a time, node by node for `[[EVM.Nodes]]`, keeping what decodes (`decodeNodeConfig`). A
block whose `ChainID` does not decode is skipped. A file that is not TOML is still an error.

## Embedded chain defaults

`integration/pkg/accessors/evmconfig/chaindefaults/` holds two copies, embedded with `go:embed`:
`chainlink-evm/` (the linked module's `pkg/config/toml/defaults`) and `ccip/` (chainlink's
`ccip/config/evm`). `chainDefaults(chainID)` layers CCIP's `fallback.toml`, then chainlink-evm's
file for the chain, then CCIP's file for it, which is how chainlink-evm applies `CL_CHAIN_DEFAULTS`.
The loader is lenient (unknown keys skipped, a bad file skipped) and reports what it skipped through
`ChainDefaultsProblems`, which the accessor logs at warn on startup. `convertFinality` uses the
same defaults, so finality conversion matches the `ccip` image too. When `CL_CHAIN_DEFAULTS` is
set, chainlink-evm's own result is used unchanged.

Tests: `TestChainDefaultsMatchACCIPNodeImage` compares `chainDefaults` with chainlink-evm's own
`CL_CHAIN_DEFAULTS` loading, in a child process, for every chain either layer has a file for.
`TestEmbeddedChainlinkEVMDefaultsMatchTheLinkedModule` fails when the embedded chainlink-evm copy no
longer matches the linked module.

## Conversion warnings

Removed: `chain <id>: dropped set chain-level settings with no standalone equivalent: <paths>`.
Added, file-level: `[[EVM]] entry <n>: skipped, its ChainID does not decode`. Added, per chain, in
this order:

- `chain <id>: dropped set settings this release cannot decode: <paths>` (chain-level paths, and `Nodes[<i>].<key>` for node settings)
- `chain <id>: dropped set chain-level settings unknown to this release: <paths>` (keys the typed config has no field for)
- `chain <id>: standalone sets these itself, overriding the node config: <path> = <value>, ...`
- `chain <id>: turned off Transactions.AutoPurge: TXM v2 detects stuck transactions by Transactions.AutoPurge.Threshold alone, and it is missing or zero`
- `chain <id>: dropped KeySpecific: its entries name the node's own keys, and the standalone executor transmits from a new one`
- `chain <id>: dropped chain-level settings this release rejects: <paths> (<validation error>)`

Node-level warnings (send-only nodes, `HTTPURLExtraWrite`, `IsLoadBalancedRPC`) are unchanged.

## inspect-config report

New top-level fields: `chain_defaults` (`ChainDefaultsSource()`) and `chain_defaults_problems`
(omitted when empty).

## Keeping the defaults current

`tools/bin/sync-chain-defaults.sh [ref]` replaces `chaindefaults/chainlink-evm` from the module
cache at the `go.mod` version, and, given a ref, `chaindefaults/ccip` from chainlink's
`ccip/config/evm` (sparse git fetch). It records both sources in `chaindefaults/README.md`.
