# Robust EVM node-config conversion for the CL→standalone cutover

## Executive Summary

- The CL node-config conversion is now total: a chain that cannot run standalone (unknown chain
  ID, no usable RPC endpoint, unservable finality mode) is skipped with its reason recorded in the
  new `Conversion.FailedChains` instead of aborting the whole file. A file where no enabled chain
  converts at all is still an error, now naming every reason.
- New boot-time guard: `NewBootstrapper` cross-checks the bootstrap config's `[[chains]]`
  declaration against each chain family's own mounted config and refuses to start on a
  declared-but-unservable chain, with chain and reason in the error. The mechanism is
  chain-agnostic: bootstrap only groups the declaration by family and calls the family's registered
  `chainaccess.DeclaredChainCoverageChecker`; the EVM driver registers the only checker today, and
  other families opt in the same way when they gain a family-local config. An explicitly disabled
  chain passes the check — that is a choice, not a gap: failing the boot would crash-loop a
  legitimate incident-remediation state. The skip still warns at startup and the declaration still
  registers the signing key in JD.
- Set-but-dropped detection now reads the mounted file's raw keys instead of the decoded
  chainlink-evm struct. What carries over is unchanged; only the warnings grow. The warnings now
  also name settings the pinned chainlink-evm has no field for (options a newer node version added,
  typos of real ones — `FinalityDepht = 22` silently reverting to the chain default was the
  motivating case), non-pointer scalar leaves, and any set node-level key beyond Name, HTTPURL,
  WSURL, Order and SendOnly. New `Conversion.IgnoredSections` names the top-level sections outside
  `[[EVM]]` (`Log`, `WebServer`, `P2P`, …).
- TXM v2 block time no longer falls back to 2 seconds on every chain. `ResolveTXMBlockTime`
  consults a curated per-chain table covering the chains whose real block interval exceeds the
  2-second floor upstream validation enforces: Ethereum, Sepolia and Holesky at 12s, Rootstock at
  30s, Gnosis and Chiado at 5s, Shibarium at 5s, Astar and Bittensor at 12s, Core, Ronin and Scroll
  at 3s. The source of the value is visible everywhere the value is: `txm_block_time_source` in the
  inspect-config diff (`operator` / `curated_chain_default` / `generic_fallback`) and an info/warn
  log at TXM start. A negative `txm_block_time` is now a validation error naming the chain and
  value instead of a `commonconfig.MustNewDuration` panic.
- Consumers: both `LoadConfigFile` callers (the EVM accessor factory and `ccv migrate
  inspect-config`) and every `bootstrap.Run` binary are in this repository and were updated.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `setChainSettingPaths` | removed | — | replaced by `droppedChainSettingPaths` | [#why-the-detection-reads-the-file](#why-the-detection-reads-the-file) |
| `convertNodes` | signature-changed | `func convertNodes\(` | `integration/pkg/accessors/evmconfig/clnode_config.go:398` | [#why-the-detection-reads-the-file](#why-the-detection-reads-the-file) |
| `standaloneChain.txmBlockTimeIsDefault → standaloneChain.txmBlockTimeSource` | renamed | `txmBlockTimeIsDefault` | `integration/pkg/accessors/evm/standalone_chain.go:72` | [#migration-guide](#migration-guide) |
| `convertChainlinkNodeConfig` | behavior-changed | `config has no usable EVM chains` | `integration/pkg/accessors/evmconfig/clnode_config.go:79` | [#why-skips-replace-per-chain-errors](#why-skips-replace-per-chain-errors) |
| `NewBootstrapper` | behavior-changed | `CheckDeclaredChainCoverage` | `bootstrap/bootstrap.go:306` | [#migration-guide](#migration-guide) |
| `CreateEVMAccessorFactory` | behavior-changed | `IgnoredSections` | `integration/pkg/accessors/evm/factory_constructor.go:65` | [#migration-guide](#migration-guide) |
| `DefaultTXMBlockTime` | behavior-changed | `DefaultTXMBlockTime` | `integration/pkg/accessors/evmconfig/chainlink_config.go:20` | [#migration-guide](#migration-guide) |
| `Conversion.FailedChains` | added | `FailedChains \[\]ChainFailure` | `integration/pkg/accessors/evmconfig/clnode_config.go:52` | [#migration-guide](#migration-guide) |
| `Conversion.DisabledChains` | added | `DisabledChains \[\]string` | `integration/pkg/accessors/evmconfig/clnode_config.go:56` | [#migration-guide](#migration-guide) |
| `Conversion.IgnoredSections` | added | `IgnoredSections \[\]string` | `integration/pkg/accessors/evmconfig/clnode_config.go:43` | [#why-the-detection-reads-the-file](#why-the-detection-reads-the-file) |
| `ChainFailure` | added | `type ChainFailure struct` | `integration/pkg/accessors/evmconfig/clnode_config.go:61` | [#migration-guide](#migration-guide) |
| `droppedChainSettingPaths` | added | `func droppedChainSettingPaths\(` | `integration/pkg/accessors/evmconfig/clnode_config.go:353` | [#why-the-detection-reads-the-file](#why-the-detection-reads-the-file) |
| `droppedNodeSettingPaths` | added | `func droppedNodeSettingPaths\(` | `integration/pkg/accessors/evmconfig/clnode_config.go:374` | [#why-the-detection-reads-the-file](#why-the-detection-reads-the-file) |
| `chainaccess.DeclaredChainCoverageChecker` | added | `type DeclaredChainCoverageChecker` | `pkg/chainaccess/coverage.go:20` | [#migration-guide](#migration-guide) |
| `chainaccess.RegisterDeclaredChainCoverageChecker` | added | `func RegisterDeclaredChainCoverageChecker\(` | `pkg/chainaccess/coverage.go:30` | [#migration-guide](#migration-guide) |
| `chainaccess.CheckDeclaredChainCoverage` | added | `func CheckDeclaredChainCoverage\(` | `pkg/chainaccess/coverage.go:44` | [#migration-guide](#migration-guide) |
| `evm.checkDeclaredChainCoverage` | added | `func checkDeclaredChainCoverage\(` | `integration/pkg/accessors/evm/coverage.go` | [#migration-guide](#migration-guide) |
| `ResolveTXMBlockTime` | added | `func ResolveTXMBlockTime\(` | `integration/pkg/accessors/evmconfig/chainlink_config.go:69` | [#migration-guide](#migration-guide) |
| `TXMBlockTimeSource` | added | `type TXMBlockTimeSource string` | `integration/pkg/accessors/evmconfig/chainlink_config.go:29` | [#migration-guide](#migration-guide) |
| `curatedTXMBlockTimeByChainID` | added | `var curatedTXMBlockTimeByChainID` | `integration/pkg/accessors/evmconfig/chainlink_config.go:50` | [#migration-guide](#migration-guide) |
| `EffectiveChain.TXMBlockTimeSource` | added | `txm_block_time_source` | `integration/pkg/accessors/evmconfig/effective_config.go:26` | [#migration-guide](#migration-guide) |
| `configReport.IgnoredSections` | added | `ignored_top_level_sections` | `cli/migrate/inspect_config.go:56` | [#migration-guide](#migration-guide) |
| `configReport.FailedChains` | added | `failed_chains` | `cli/migrate/inspect_config.go:59` | [#migration-guide](#migration-guide) |

## Breaking Changes

### `NewBootstrapper` fails the boot on a declared-but-unservable chain

- **What changed:** `NewBootstrapper` (and so every `bootstrap.Run` binary) runs each registered
  family's declared-chain coverage check at boot and fails on a declared-but-unservable chain.
- **Before:** the gap surfaced only when the first message for the chain arrived.
- **After:** the process refuses to start, with the chain and reason in the error.
- **Why:** a declared chain the config cannot serve is an operator error that should fail fast, not
  at first traffic.
- **Who is affected:** only the EVM driver registers a checker today, so non-EVM deployments are
  unaffected by construction; deployments whose declaration and config already agree are
  unaffected; a process declaring no chains skips the check entirely.

### The node-config conversion returns per-chain failures as data

- **What changed:** `convertChainlinkNodeConfig` no longer errors on the first unservable chain.
- **Before:** one leftover `[[EVM]]` block aborted conversion of the whole file.
- **After:** per-chain failures are `Conversion.FailedChains` data; only a file with zero usable
  chains errors.
- **Why:** the strictness moved to the layer that can judge it — the operator's own `[[chains]]`
  declaration, enforced at boot — while the conversion stays total so a pre-cutover review sees
  every problem in one run.
- **Who is affected:** both callers (`LoadConfigFile` consumers: the accessor factory and
  `inspect-config`) are in this repository and were updated. Error-message texts for the per-chain
  cases moved into `ChainFailure.Reason`; the substrings the old errors carried (`no known chain
  selector`, `no [[EVM.Nodes]] entries`, `no HTTPURL`, `no usable [[EVM.Nodes]] entries`) are
  unchanged.

Not a break, but a behavior change: operators who set no TXM block time on Ethereum, Rootstock,
Gnosis, Shibarium, Astar, Bittensor, Core, Ronin or Scroll (or the covered testnets) will run the
curated interval instead of 2s — a slower, fee-cheaper rebroadcast cadence, matching what TXM v1's
block-count-based bumping produced on those chains. `txm_block_time_is_default` in the
inspect-config report keeps its meaning (true whenever the operator set nothing); the new
`txm_block_time_source` field says which default fired.

## Migration Guide

1. Already-consistent deployments: no steps.
2. If a process fails to boot with `bootstrap config declares EVM chains the mounted EVM config
   cannot serve`, the error names each chain and its reason; either fix that chain's `[[EVM]]`
   section in the mounted config or remove the chain from `[[chains]]`.
3. Pre-cutover review: `ccv migrate inspect-config` shows the same skips under `failed_chains`
   before anything starts (narrowing to a skipped chain with `--chain-selector` reports its failure
   instead of a bare not-in-config error), and prints the ignored top-level sections as
   `ignored_top_level_sections` (file-level, so the list does not narrow). The diff and the startup
   log may name settings earlier runs did not show — options the tool's chainlink-evm version
   predates, and typos. Each named setting was already being dropped; the change only makes the
   drop visible.
4. TXM block time: operators who agreed an explicit per-chain value with Chainlink Labs keep it —
   it overrides the curated table. Treat `generic_fallback` on a chain you know to be slower than
   2s as the one remaining case that needs an explicit value, and report it so the curated table
   can grow. The table is intended to move upstream into chainlink-evm's per-chain defaults once
   the values have production mileage.

## Why the detection reads the file

The typed walk had three blind spots: a setting the pinned chainlink-evm version has no field for
(the TOML decoder ignores unknown keys), a non-pointer scalar leaf (set looks like unset), and any
node field beyond the fixed two-item list. Reading the file's own keys closes all three at once and
cannot drift from what the operator wrote. The typed decode stays authoritative for the conversion
itself; the raw pass only produces warnings, and a raw failure degrades warnings rather than
failing a loadable config.

## Why skips replace per-chain errors

The conversion used to fail the whole file on the first unservable chain, so one leftover `[[EVM]]`
block — a chain whose RPC was decommissioned, a typo'd chain ID — took every other chain down with
it. Meanwhile the verifier's own startup already tolerates a per-chain accessor failure by logging
and skipping. The strictness moved to the layer that can judge it: the operator's own declaration
of served chains (`[[chains]]`) is the backstop, enforced at boot through the family's registered
coverage checker (`chainaccess.CheckDeclaredChainCoverage`; the EVM driver's checker compares
against the mounted EVM config), while the conversion stays total so a pre-cutover review sees
every problem in one run.

Covered by `TestConvertChainlinkNodeConfigSkipsUnservableChains`,
`TestDeclaredChainCoverageCheckers` (the family-agnostic mechanics), `TestCheckDeclaredChainCoverage`
(the EVM checker), `TestNewBootstrapperDeclaredChainCoverage` (the bootstrap wiring),
`TestConvertChainlinkNodeConfigWarnsAboutSettingsUnknownToTheTypedConfig`,
`TestConvertChainlinkNodeConfigNamesIgnoredTopLevelSections`,
`TestConvertChainlinkNodeConfigWarnsAboutSettingsFromMergedBlocks`, `TestResolveTXMBlockTime`,
`TestCuratedTXMBlockTimesRespectTheUpstreamFloor`, `TestBuildChainlinkEVMTOMLAppliesTheResolvedBlockTime`,
`TestBuildChainlinkEVMTOMLRejectsANegativeBlockTime`, the updated `TestEffectiveChainConfigs`, and
the `failed chain`, `ignored top-level sections` and block-time subtests of `TestBuildConfigReport`.

## References

- PR: https://github.com/smartcontractkit/chainlink-ccv/pull/1461
