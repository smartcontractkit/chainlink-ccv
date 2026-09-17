# Curated per-chain TXM v2 block-time defaults

## Executive Summary

- A chain with no operator-set TXM v2 block time no longer falls back to 2 seconds on every chain.
  `BuildChainlinkEVMTOML` now resolves through a curated per-chain table covering the chains whose
  real block interval exceeds the 2-second floor upstream validation enforces: Ethereum, Sepolia
  and Holesky at 12s, Rootstock at 30s, Gnosis and Chiado at 5s, Shibarium at 5s, Astar and
  Bittensor at 12s, Core, Ronin and Scroll at 3s. On a 12s chain the old fallback bumped fees at 6s
  instead of the intended 36s (`RetryBlockThreshold` 3 × `BlockTime`).
- Chains at or below 2 seconds are deliberately not in the table: upstream rejects
  `BlockTime < 2s` (`chainlink-evm` `TransactionManagerV2Config.ValidateConfig`), so the generic
  fallback is already their best legal value.
- The source of the value is visible everywhere the value is: `txm_block_time_source` in the
  `inspect-config` diff (`operator` / `curated_chain_default` / `generic_fallback`), an info log at
  TXM start for a curated default, and the existing warn — now scoped to chains with no curated
  entry — for the generic fallback. An explicit `txm_block_time` always wins.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `ResolveTXMBlockTime` | added | `func ResolveTXMBlockTime\(` | `integration/pkg/accessors/evmconfig/chainlink_config.go` | [#migration-guide](#migration-guide) |
| `TXMBlockTimeSource` | added | `type TXMBlockTimeSource string` | `integration/pkg/accessors/evmconfig/chainlink_config.go` | [#migration-guide](#migration-guide) |
| `curatedTXMBlockTimeByChainID` | added | `var curatedTXMBlockTimeByChainID` | `integration/pkg/accessors/evmconfig/chainlink_config.go` | [#migration-guide](#migration-guide) |
| `DefaultTXMBlockTime` | semantics-changed | `DefaultTXMBlockTime` | `integration/pkg/accessors/evmconfig/chainlink_config.go` | [#migration-guide](#migration-guide) |
| `EffectiveChain.TXMBlockTimeSource` | added | `txm_block_time_source` | `integration/pkg/accessors/evmconfig/effective_config.go` | [#migration-guide](#migration-guide) |
| `standaloneChain.txmBlockTimeIsDefault` | replaced | `txmBlockTimeSource` | `integration/pkg/accessors/evm/standalone_chain.go` | [#migration-guide](#migration-guide) |

## Breaking Changes

No config or API breaks. Behavior change: operators who set no block time on Ethereum, Rootstock,
Gnosis, Shibarium, Astar, Bittensor, Core, Ronin or Scroll (or the covered testnets) will run the
curated interval instead of 2s — a slower, fee-cheaper rebroadcast cadence, matching what TXM v1's
block-count-based bumping produced on those chains. `txm_block_time_is_default` in the
inspect-config report keeps its meaning (true whenever the operator set nothing); the new
`txm_block_time_source` field says which default fired.

## Migration Guide

No steps. Operators who agreed an explicit per-chain value with Chainlink Labs keep it — it
overrides the table. Reviewers reading the pre-cutover diff should treat `generic_fallback` on a
chain they know to be slower than 2s as the one remaining case that needs an explicit value, and
report it so the curated table can grow. The table is intended to move upstream into
chainlink-evm's per-chain defaults once the values have production mileage.

Covered by `TestResolveTXMBlockTime`, `TestCuratedTXMBlockTimesRespectTheUpstreamFloor`,
`TestBuildChainlinkEVMTOMLAppliesTheResolvedBlockTime`, and the updated `TestEffectiveChainConfigs`
and `TestBuildConfigReport` subtests.
