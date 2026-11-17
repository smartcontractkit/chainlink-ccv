# Per-chain gas overrides for FeeQuoter updatePrices

## Executive Summary

- Adds an optional per-chain `fee_quoter_gas_overrides` config that sets the gas limit of the FeeQuoter `updatePrices` transaction.
- Previously the limit was hardcoded (`100_000 + 50_000 * updates`) and could not be tuned for chains where that is too low or too high.
- Affects `pkg/chainaccess.PricerConfig` consumers (the pricer service) and the EVM accessor's FeeQuoter writer.
- Non-breaking: with no override configured, gas limits are identical to before.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `chainaccess.PricerConfig.FeeQuoterGasOverrides` | added | `FeeQuoterGasOverrides\b` | `pkg/chainaccess/registry.go:82` | [#config](#config) |
| `chainaccess.FeeQuoterGasOverride` | added | `FeeQuoterGasOverride\b` | `pkg/chainaccess/registry.go:87` | [#config](#config) |
| `pricereader.WithUpdatePricesGas` | added | `WithUpdatePricesGas\b` | `integration/pkg/pricereader/fee_quoter_writer.go:75` | [#writer-option](#writer-option) |
| `evm.chainRuntime.NewFeeQuoterWriter` (unexported) | signature-changed | `\) NewFeeQuoterWriter\(` | `integration/pkg/accessors/evm/standalone_chain.go:97` | [#internal-changes](#internal-changes) |

## Breaking Changes

*No breaking changes.* Every changed signature is unexported (see [Internal changes](#internal-changes)).

## New Features / Additions

### Config

`PricerConfig` gains an optional map keyed by chain selector, next to `fee_quoter_addresses` and `native_token_decimals`:

```toml
[fee_quoter_gas_overrides.5009297550715157269]
base_gas       = 150000
gas_per_update = 60000
```

- Gas limit = `base_gas + gas_per_update * (token price updates + gas price updates)`.
- A zero or omitted field keeps its default (`base_gas` 100000, `gas_per_update` 50000).
- A chain without an entry keeps both defaults.
- The table is top-level, not under `[[chains]]`. Apps that embed `chainaccess.PricerConfig` (such as the pricer service) accept it without code changes.
- Selectors are not checked against configured chains. An entry for an unconfigured chain is ignored.

### Writer option

`pricereader.WithUpdatePricesGas(baseGas, gasPerUpdate uint64) WriterOption` overrides the limit on an `EVMFeeQuoterWriter`. Zero values keep the defaults.

## Compatibility & Requirements

- **Dependency bump:** consumers must bump `chainlink-ccv` to a version with this change for `fee_quoter_gas_overrides` to take effect. On an older version the key is silently ignored.
- **Rollout:** no flag. The default behavior is unchanged.

## Internal changes

These are unexported and do not affect consumers outside the package:

- `pricereader` constants `updatePricesBaseGas` / `updatePricesGasPerUpdate` are renamed `defaultUpdatePricesBaseGas` / `defaultUpdatePricesGasPerUpdate`.
- `evm.chainRuntime.NewFeeQuoterWriter` takes a trailing `...pricereader.WriterOption`.
- `evm.newFactory` takes a new `feeQuoterGasOverrides` argument after `nativeDecimals`.
