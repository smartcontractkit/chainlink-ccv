# FeeQuoterWriter can estimate the cost of an updatePrices transaction

## Executive Summary

- `chainaccess.FeeQuoterWriter` gains `EstimateUpdateCost`, which returns the worst-case cost of the `updatePrices` transaction that `UpdatePrices` would send for the same updates, without sending it.
- The cost is in whole native tokens with 1e36 precision, the same scale as `GasPriceReader.GetGasPrice`, so a caller can combine it with a USD price of the native token.
- `pricereader.NewEVMFeeQuoterWriter` now requires the chain's native token decimals and returns an error, following `NewEVMGasPriceReader`.
- Affects every implementer of `chainaccess.FeeQuoterWriter` (including test fakes) and every caller of `NewEVMFeeQuoterWriter`. `EVMFeeQuoterWriter` is the only production implementation.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `pricereader.NewEVMFeeQuoterWriter` | signature-changed | `NewEVMFeeQuoterWriter\(` | `integration/pkg/pricereader/fee_quoter_writer.go:102` | [#newevmfeequoterwriter-takes-native-decimals-and-returns-an-error](#newevmfeequoterwriter-takes-native-decimals-and-returns-an-error) |
| `chainRuntime.NewFeeQuoterWriter` (`integration/pkg/accessors/evm`) | signature-changed | `\.NewFeeQuoterWriter\(` | `integration/pkg/accessors/evm/standalone_chain.go:97` | [#chainruntimenewfeequoterwriter-takes-native-decimals](#chainruntimenewfeequoterwriter-takes-native-decimals) |
| `chainaccess.FeeQuoterWriter.EstimateUpdateCost` | added | `\bEstimateUpdateCost\b` | `pkg/chainaccess/interfaces.go:164` | [#estimateupdatecost-added-to-the-interface](#estimateupdatecost-added-to-the-interface) |
| `pricereader.EVMFeeQuoterWriter.EstimateUpdateCost` | added | `\bEstimateUpdateCost\b` | `integration/pkg/pricereader/fee_quoter_writer.go:133` | [#estimateupdatecost-added-to-the-interface](#estimateupdatecost-added-to-the-interface) |
| `pricereader.WithFeeEstimator` | added | `\bWithFeeEstimator\b` | `integration/pkg/pricereader/fee_quoter_writer.go:84` | [#withfeeestimator-option](#withfeeestimator-option) |
| `pricereader.EVMFeeQuoterWriter.UpdatePrices` with nothing to send | behavior-changed | `no token and gas price updates` | `integration/pkg/pricereader/fee_quoter_writer.go:167` | [#updateprices-and-estimateupdatecost-share-one-code-path](#updateprices-and-estimateupdatecost-share-one-code-path) |

## Breaking Changes

### NewEVMFeeQuoterWriter takes native decimals and returns an error

- **What changed:** `pricereader.NewEVMFeeQuoterWriter`.
- **Before:** `NewEVMFeeQuoterWriter(lggr, client, address, opts ...WriterOption) *EVMFeeQuoterWriter`
- **After:** `NewEVMFeeQuoterWriter(lggr, client, address, nativeDecimals uint8, opts ...WriterOption) (*EVMFeeQuoterWriter, error)`
- **Why:** `EstimateUpdateCost` needs the native token decimals to scale to 1e36. A required argument validated at construction matches `NewEVMGasPriceReader(client, daOracle, nativeDecimals)`, so a wrong value cannot fall back silently to 18.
- **Who is affected:** every caller. The error is returned when `nativeDecimals` is above `pricereader.MaxNativeTokenDecimals` (36).
- **Value to pass:** the same value given to `NewEVMGasPriceReader` for that chain, 18 for most chains.

### chainRuntime.NewFeeQuoterWriter takes native decimals

- **What changed:** the unexported `chainRuntime` interface in `integration/pkg/accessors/evm` has `NewFeeQuoterWriter(ctx, ks, keyName, feeQuoterAddress, tokens, nativeDecimals uint8)`.
- **Who is affected:** custom `chainRuntime` implementations, including test stubs. The accessor passes the chain's configured native decimals.

### EstimateUpdateCost added to the interface

- **What changed:** `chainaccess.FeeQuoterWriter` has a new method `EstimateUpdateCost(ctx context.Context, tokenPrices []protocol.FeeTokenPriceUpdate, gasPrices []protocol.GasTokenPriceUpdate) (*big.Int, error)`.
- **Who is affected:** every implementer of `chainaccess.FeeQuoterWriter` must add it or stop compiling. This includes fakes and stubs in tests.
- **Result:** the worst-case cost in whole native tokens with 1e36 precision. The estimator's cost in the smallest native unit (wei on EVM) is multiplied by `10^(36 - nativeDecimals)`, so 1 wei on an 18-decimal chain is `1e18`. Nothing is sent.
- **Errors:** `EVMFeeQuoterWriter` returns an error when it has no estimator (see `WithFeeEstimator`), when it has no sender address (no `WithTxm`), when there is nothing to update, or when the estimator fails. An estimate failure does not affect `UpdatePrices`.

## Migration Guide

1. Update every `NewEVMFeeQuoterWriter` call:

```go
// Before
writer := pricereader.NewEVMFeeQuoterWriter(lggr, client, address, pricereader.WithTokenCache(cache))
```

```go
// After
writer, err := pricereader.NewEVMFeeQuoterWriter(lggr, client, address, nativeDecimals, pricereader.WithTokenCache(cache))
if err != nil {
	return err
}
```

2. Add `EstimateUpdateCost` to any custom or fake `FeeQuoterWriter`:

```go
func (f *fake) EstimateUpdateCost(context.Context, []protocol.FeeTokenPriceUpdate, []protocol.GasTokenPriceUpdate) (*big.Int, error) {
	return new(big.Int), nil
}
```

3. When wiring `EVMFeeQuoterWriter` by hand, pass `pricereader.WithFeeEstimator(estimator, priceMaxKey)` so `EstimateUpdateCost` works. `estimator` is the `gas.EvmFeeEstimator` the TXM uses, and `priceMaxKey` is the TXM's per-sender fee-cap callback (`txmgr.NewEvmTxmFeeConfig(gasConfig).PriceMaxKey`, where `gasConfig` is the chain's gas estimator configuration). Writers built through `standaloneChain.NewFeeQuoterWriter` already have both.
4. Add the `nativeDecimals uint8` parameter to any custom `NewFeeQuoterWriter` on a `chainRuntime`.
5. Regenerate mocks if the repo mocks this interface: `just generate`.

## New Features / Additions

### WithFeeEstimator option

`pricereader.WithFeeEstimator(estimator, priceMaxKey)` gives the writer a fee estimator and the TXM's sender fee-cap callback (`func(common.Address) *assets.Wei`). The estimator must implement `GetMaxCost`, which `gas.EvmFeeEstimator` from `chainlink-evm` satisfies, and the callback must return a non-nil cap for each sender. Without these dependencies `EstimateUpdateCost` returns an error; `UpdatePrices` does not use them.

- `standaloneChain` keeps the estimator it builds for the TXM in a new `feeEstimator` field (`integration/pkg/accessors/evm/standalone_chain.go`) and passes it in `NewFeeQuoterWriter`. The writer and the TXM therefore use the same estimator.
- The accessor factory builds the log-only writer next to the gas price reader and passes both the same `nativeDecimals`. A failure to build it fails accessor construction, as the gas price reader's does.

### UpdatePrices and EstimateUpdateCost share one code path

`EVMFeeQuoterWriter.UpdatePrices` was split. Token decimals, price scaling and packing now live in `buildPriceUpdates`, and the gas limit comes from `updatePricesFeeLimit`. `UpdatePrices` and `EstimateUpdateCost` both use them, so an estimate is computed from the same calldata and gas limit that would be sent.

Both return an error when there is nothing to send: `no token and gas price updates to be made` for an empty input, and `no gas price updates, and unable to get all token decimals` when every token update lost its decimals and no gas update remains.

The estimate uses the first configured sender address and does not call `GetNextAddress`, so estimating does not advance the key round-robin. The `Submitted fee quoter price update to txm` log now also carries `feeLimit`.

## Compatibility & Requirements

- **How the number is computed:** `gas.EvmFeeEstimator.GetMaxCost` returns `maxFeePrice × gasLimit` (`GasFeeCap` when EIP-1559 is enabled, otherwise `GasPrice`) in the smallest native unit. The writer then multiplies by `10^(36 - nativeDecimals)`. It is an upper bound, usually above the actual cost.
- **Gas limit:** the writer passes its static limit (`updatePricesBaseGas + updatePricesGasPerUpdate × updates`). The estimator uses it as is when the chain has `EstimateLimit = false`, which is the default. With `EstimateLimit = true` (Hedera mainnet and testnet) the estimator calls `eth_estimateGas`, uses the estimate × 1.15 as the gas limit, and fails with `ErrFeeLimitTooLow` if the estimate exceeds the static limit.
- **Unit on Hedera:** the cost is in the unit of the RPC gas price, so `nativeDecimals` must match what the gas price reader uses for that chain, not necessarily the token's own decimals.
- **Extra RPC:** an estimate may call the chain (fee history or suggested price, plus `eth_estimateGas` when `EstimateLimit` is on). Call it where an RPC is acceptable, not in constructors or `Start`.
- **Consumers pinning this module:** `pricer-service` pins `chainlink-ccv` by version, so its fakes (`fakeFeeQuoterWriter`, `fakeWriter`) only need the new method when its `go.mod` moves to a version with this change.

## References

- Prior changelog entries this builds on: [2026-11-13_fee_quoter_writer_transaction_status.md](2026-11-13_fee_quoter_writer_transaction_status.md)
