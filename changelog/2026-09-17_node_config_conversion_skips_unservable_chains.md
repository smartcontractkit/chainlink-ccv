# Node-config conversion skips unservable chains, and the bootstrapper enforces declared-chain coverage

## Executive Summary

- The CL node-config conversion no longer aborts on a chain that cannot run standalone (unknown
  chain ID, no usable RPC endpoint, unservable finality mode). The chain is skipped, recorded in
  the new `Conversion.FailedChains` with the reason, warned about in the startup log, and every
  other chain still converts. A file where no enabled chain converts at all is still an error, now
  naming every reason.
- New boot-time guard: `NewBootstrapper` cross-checks the bootstrap config's `[[chains]]`
  declaration against each chain family's own mounted config and refuses to start when a declared
  chain is not servable, with the chain and reason in the error. The mechanism is chain-agnostic:
  bootstrap only groups the declaration by family and calls the family's registered
  `chainaccess.DeclaredChainCoverageChecker`; the EVM driver registers one (against the mounted EVM
  config / converted node TOML), and other families opt in the same way when they gain a
  family-local config. Previously that gap surfaced only when the first message for the chain
  arrived.
- `ccv migrate inspect-config` prints the skips as `failed_chains`, and narrowing to a skipped
  chain with `--chain-selector` reports its failure instead of a bare not-in-config error.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `Conversion.FailedChains` | added | `FailedChains \[\]ChainFailure` | `integration/pkg/accessors/evmconfig/clnode_config.go` | [#migration-guide](#migration-guide) |
| `ChainFailure` | added | `type ChainFailure struct` | `integration/pkg/accessors/evmconfig/clnode_config.go` | [#migration-guide](#migration-guide) |
| `convertChainlinkNodeConfig` | behavior-changed | `config has no usable EVM chains` | `integration/pkg/accessors/evmconfig/clnode_config.go` | [#why-skips-replace-per-chain-errors](#why-skips-replace-per-chain-errors) |
| `chainaccess.DeclaredChainCoverageChecker` | added | `type DeclaredChainCoverageChecker` | `pkg/chainaccess/coverage.go` | [#migration-guide](#migration-guide) |
| `chainaccess.CheckDeclaredChainCoverage` | added | `func CheckDeclaredChainCoverage\(` | `pkg/chainaccess/coverage.go` | [#migration-guide](#migration-guide) |
| `checkDeclaredChainCoverage` (EVM) | added | `func checkDeclaredChainCoverage\(` | `integration/pkg/accessors/evm/coverage.go` | [#migration-guide](#migration-guide) |
| `NewBootstrapper` | behavior-changed | `CheckDeclaredChainCoverage` | `bootstrap/bootstrap.go` | [#migration-guide](#migration-guide) |
| `configReport.FailedChains` | added | `failed_chains` | `cli/migrate/inspect_config.go` | [#migration-guide](#migration-guide) |

## Breaking Changes

- `NewBootstrapper` (and so every `bootstrap.Run` binary) now runs each registered family's
  declared-chain coverage check at boot and fails on a declared-but-unservable chain. Only the EVM
  driver registers a checker today, so non-EVM deployments are unaffected by construction;
  deployments whose declaration and config already agree are unaffected; a process declaring no
  chains skips the check entirely.
- `convertChainlinkNodeConfig` returns per-chain failures as data instead of erroring on the first
  one. Both callers (`LoadConfigFile` consumers: the accessor factory and `inspect-config`) are in
  this repository and were updated. Error-message texts for the per-chain cases moved into
  `ChainFailure.Reason`; the substrings the old errors carried (`no known chain selector`,
  `no [[EVM.Nodes]] entries`, `no HTTPURL`, `no usable [[EVM.Nodes]] entries`) are unchanged.

## Migration Guide

No steps for already-consistent deployments. If a process fails to boot with `bootstrap config
declares EVM chains the mounted EVM config cannot serve`, the error names each chain and its
reason; either fix that chain's `[[EVM]]` section in the mounted config or remove the chain from
`[[chains]]`. The pre-cutover diff (`ccv migrate inspect-config`) shows the same skips under
`failed_chains` before anything starts.

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
(the EVM checker), `TestNewBootstrapperDeclaredChainCoverage` (the bootstrap wiring), and the
`failed chain` subtests of `TestBuildConfigReport`.
