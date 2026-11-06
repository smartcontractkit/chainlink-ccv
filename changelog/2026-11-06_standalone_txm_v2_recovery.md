# Standalone TXM v2 recovery pricing and retry cadence

## Executive Summary

- TXM v2 purge and nonce-gap attempts now have a legacy-fee fallback for estimators whose `GetMaxFee` is unsupported.
- `BumpThreshold = 0` now maps to v1's `ResendAfterThreshold` cadence instead of rebroadcasting every TXM tick.
- The curated block-time table gains the testnet counterparts of its mainnet entries and Ethereum Hoodi.
- These changes affect transaction recovery and retries, not transaction contents or CCV interfaces.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evm.newTxmV2` | behavior-changed | `newTxmV2\(` | `integration/pkg/accessors/evm/txm.go` | [#recovery-pricing](#recovery-pricing) |
| `curatedTXMBlockTimeByChainID` | behavior-changed | `curatedTXMBlockTimeByChainID` | `integration/pkg/accessors/evmconfig/chainlink_config.go` | [#retry-cadence](#retry-cadence) |
| `evm.withPurgeFeeFallback` | added | `withPurgeFeeFallback\(` | `integration/pkg/accessors/evm/purge_fee.go` | [#recovery-pricing](#recovery-pricing) |
| `evm.retryBlockThreshold` | added | `retryBlockThreshold\(` | `integration/pkg/accessors/evm/txm.go` | [#retry-cadence](#retry-cadence) |

## Breaking Changes

*No breaking changes.*

## Recovery pricing

Upstream TXM v2 calls `GetMaxFee` for purgeable nonce-gap and orphan-recovery attempts. `FeeHistory` in legacy mode and `SuggestedPrice` do not implement that call, so those attempts previously could not be built even though normal transactions worked.

`withPurgeFeeFallback` wraps only estimator modes without a max fee. Its fallback starts with `GetFee`, applies v1's bump rule six times, and caps the result at the key's `PriceMax`. Six bumps are one more than TXM v2 applies to an ordinary attempt, allowing a same-market replacement to outbid the prior process's highest attempt. Estimators with a working `GetMaxFee` remain unchanged.

## Retry cadence

A positive `BumpThreshold` passes through, clamped to `MaxUint16` instead of wrapping. Zero becomes `ceil(ResendAfterThreshold / BlockTime)`, or `MaxUint16` when resend is disabled. This preserves v1's behavior for Hedera, whose zero threshold disables gas bumps but still permits timed resends.

The curated table now covers Rootstock testnet, Hoodi, Shibarium Puppynet, Astar Shibuya, Bittensor testnet, Core testnet2, Ronin Saigon, and Scroll Sepolia with the same intervals as their corresponding networks. Explicit `txm_block_time` configuration still takes precedence.

## References

- Prior changelog entry: `2026-11-03_evm_node_chain_settings_parity.md`
