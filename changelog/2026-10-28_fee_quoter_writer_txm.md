# EVM fee quoter writer sends `updatePrices` through the TXM

## Executive Summary

- The EVM accessor's `FeeQuoterWriter` now submits `FeeQuoter.updatePrices` transactions through the chain's TXM v2 instead of only logging the update.
- `pricereader.LoggingFeeQuoterWriter` is renamed `pricereader.EVMFeeQuoterWriter`; it scales token prices by the token's decimals, packs gas prices, and applies a Hedera gas price scale-down.
- The TXM is now shared between the executor's contract transmitter and the fee quoter writer, so a pricer-only chain can sign and send price updates.
- Breaking only for code that constructs the writer directly (constructor rename). Accessor consumers see no API change; prices start going on chain once the keystore is set.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `pricereader.LoggingFeeQuoterWriter → pricereader.EVMFeeQuoterWriter` | renamed | `\bLoggingFeeQuoterWriter\b` | `integration/pkg/pricereader/fee_quoter_writer.go:46` | [#writer-renamed](#writer-renamed) |
| `pricereader.NewLoggingFeeQuoterWriter → pricereader.NewEVMFeeQuoterWriter` | signature-changed | `\bNewLoggingFeeQuoterWriter\(` | `integration/pkg/pricereader/fee_quoter_writer.go:72` | [#writer-renamed](#writer-renamed) |
| `evm.chainRuntime.NewFeeQuoterWriter` | added | `chainRuntime\b` | `integration/pkg/accessors/evm/standalone_chain.go:94` | [#chainruntime-method](#chainruntime-method) |
| `accessor.FeeQuoterWriter()` | behavior-changed | `\.FeeQuoterWriter\(\)` | `integration/pkg/accessors/evm/factory.go:349` | [#on-chain-price-updates](#on-chain-price-updates) |
| `standaloneChain.NewContractTransmitter` | behavior-changed | `\.NewContractTransmitter\(` | `integration/pkg/accessors/evm/standalone_chain.go:293` | [#shared-txm](#shared-txm) |
| `pricereader.WithTxm`, `pricereader.WriterOption` | added | `\bWithTxm\(` | `integration/pkg/pricereader/fee_quoter_writer.go:63` | [#on-chain-price-updates](#on-chain-price-updates) |

## Breaking Changes

### Writer renamed

- **What changed:** `LoggingFeeQuoterWriter` and `NewLoggingFeeQuoterWriter` in `integration/pkg/pricereader`.
- **Before:** `NewLoggingFeeQuoterWriter(lggr, address)` returned a writer that only logged.
- **After:** `NewEVMFeeQuoterWriter(lggr, client, address, opts ...WriterOption)`. It needs a `batchClient` to read token decimals. Without `WithTxm(...)` it logs the update and sends nothing.
- **Why:** the type now sends transactions, so "Logging" no longer describes it, and the name matches `EVMFeeQuoterReader`.
- **Who is affected:** code that builds the writer directly. `CreateAccessor` already does this internally.

### `chainRuntime` gains a method

- **What changed:** the unexported `evm.chainRuntime` interface has a new `NewFeeQuoterWriter(ctx, ks, keyName, feeQuoterAddress)` method.
- **Who is affected:** test doubles of `chainRuntime` (for example `stubChainRuntime`) must implement it.

## Migration Guide

1. Replace `pricereader.NewLoggingFeeQuoterWriter(lggr, addr)` with `pricereader.NewEVMFeeQuoterWriter(lggr, client, addr)`.
2. To send transactions, add `pricereader.WithTxm(txm, keys, fromAddresses)`.
3. Add `NewFeeQuoterWriter` to any `chainRuntime` test double.

## New Features / Additions

### On-chain price updates

- **`EVMFeeQuoterWriter.UpdatePrices`** now does the following:
  - Reads each token's `decimals()` in one RPC batch and caches the result.
  - Scales token prices to the on-chain format: `price * 1e18 / 10^decimals`.
  - Divides Hedera mainnet and testnet gas prices (execution and DA fee) by 1e10.
  - Packs each gas price with the DA fee in the high bits above 112 bits, plus the execution fee.
  - Submits one `updatePrices` transaction to the TXM, and returns once the TXM accepts it, not once it is mined.
  - Uses a fee limit of 100k gas plus 50k per update.
  - Returns early without an RPC for an empty update.
- A failed decimals read, a nil or negative token price, or a TXM or key-picker error is returned to the caller and nothing is sent.
- `packFeeComponents` treats a nil fee as zero.

### Shared TXM

- `standaloneChain` starts the TXM on first use (`ensureTXMLocked`) and shares it between `NewContractTransmitter` and `NewFeeQuoterWriter`. The transmitter still needs an off-ramp address; the writer only needs a fee quoter address.
- The TXM is built in `SetKeystore`, not in a constructor or `Start()`.

## Compatibility & Requirements

- **Signing key:** the accessor's transmitter key (default `contracttransmitter.DefaultKeyName`, or the destination's `transmitter_key_name`) must be an authorized price updater on the FeeQuoter, or the transactions revert. The fee quoter reader already reports this as `ServiceIsAuthorized`.
- **One key per chain:** the TXM runs with one key name. Asking for a different one on the same chain returns an error.
- **Failure mode:** if the writer cannot start (for example the key is missing), startup continues, the writer stays log-only, and the accessor's `Degraded()` reports it.
- **Gas limit:** the fixed `updatePrices` fee limit is an estimate.

## References

- Prior changelog entries this builds on: `2026-05-01_executor_keystore_transmitter.md`
