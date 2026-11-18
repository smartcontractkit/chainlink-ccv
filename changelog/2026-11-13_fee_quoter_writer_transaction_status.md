# FeeQuoterWriter returns a transaction ID and exposes transaction status

## Executive Summary

- `chainaccess.FeeQuoterWriter.UpdatePrices` now returns `(string, error)` instead of `error`, and the interface gains `GetTransactionStatus`.
- Callers can now follow an `updatePrices` transaction after it is handed to the TXM; previously `UpdatePrices` returned once the TXM accepted it, with nothing to track it by.
- Affects every implementer and caller of `chainaccess.FeeQuoterWriter`, including test fakes. `EVMFeeQuoterWriter` is the only production implementation.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `chainaccess.FeeQuoterWriter.UpdatePrices` | signature-changed | `\.UpdatePrices\(` | `pkg/chainaccess/interfaces.go:161` | [#updateprices-returns-a-transaction-id](#updateprices-returns-a-transaction-id) |
| `pricereader.EVMFeeQuoterWriter.UpdatePrices` | signature-changed | `\.UpdatePrices\(` | `integration/pkg/pricereader/fee_quoter_writer.go:92` | [#updateprices-returns-a-transaction-id](#updateprices-returns-a-transaction-id) |
| `chainaccess.FeeQuoterWriter.GetTransactionStatus` | added | `\bGetTransactionStatus\b` | `pkg/chainaccess/interfaces.go:163` | [#gettransactionstatus-added-to-the-interface](#gettransactionstatus-added-to-the-interface) |
| `pricereader.EVMFeeQuoterWriter.GetTransactionStatus` | added | `\bGetTransactionStatus\b` | `integration/pkg/pricereader/fee_quoter_writer.go:305` | [#gettransactionstatus-added-to-the-interface](#gettransactionstatus-added-to-the-interface) |
| `pricereader.EVMFeeQuoterWriter` TXM idempotency key | behavior-changed | `IdempotencyKey` | `integration/pkg/pricereader/fee_quoter_writer.go:156` | [#idempotency-key-is-set-on-every-transaction](#idempotency-key-is-set-on-every-transaction) |

## Breaking Changes

### UpdatePrices returns a transaction ID

- **What changed:** `FeeQuoterWriter.UpdatePrices` and `EVMFeeQuoterWriter.UpdatePrices`.
- **Before:** `UpdatePrices(ctx, tokenPrices, gasPrices) error`
- **After:** `UpdatePrices(ctx, tokenPrices, gasPrices) (string, error)`. The string is the TXM idempotency key of the submitted transaction.
- **Why:** gives callers a handle to look the transaction up with `GetTransactionStatus`.
- **Who is affected:** every caller of `UpdatePrices` and every type implementing `chainaccess.FeeQuoterWriter` (including test fakes).
- **Empty ID:** the ID is `""` whenever no transaction was sent: nothing to update, no token had readable decimals, the writer has no TXM (log-only mode), or an error occurred.

### GetTransactionStatus added to the interface

- **What changed:** `chainaccess.FeeQuoterWriter` has a new method `GetTransactionStatus(ctx context.Context, txID string) (commontypes.TransactionStatus, error)`, where `commontypes` is `github.com/smartcontractkit/chainlink-common/pkg/types`.
- **Who is affected:** every implementer of `chainaccess.FeeQuoterWriter` must add it or stop compiling.
- **Statuses:** `Unknown`, `Pending`, `Unconfirmed`, `Finalized`, `Failed`, `Fatal`.
- **No TXM:** `EVMFeeQuoterWriter` without `WithTxm` returns `Unknown` and an error.

## Migration Guide

1. Update every `UpdatePrices` call to take two return values:

```go
// Before
err := writer.UpdatePrices(ctx, tokenPrices, gasPrices)
```

```go
// After
txID, err := writer.UpdatePrices(ctx, tokenPrices, gasPrices)
```

2. Add `GetTransactionStatus` to any custom or fake `FeeQuoterWriter`:

```go
func (f *fake) UpdatePrices(context.Context, []protocol.FeeTokenPriceUpdate, []protocol.GasTokenPriceUpdate) (string, error) {
	return "", nil
}

func (f *fake) GetTransactionStatus(context.Context, string) (commontypes.TransactionStatus, error) {
	return commontypes.Unknown, nil
}
```

3. Treat an empty `txID` with a nil error as "nothing was sent"; do not pass it to `GetTransactionStatus`.

## New Features / Additions

- **Transaction tracking for fee quoter updates** — `txID, _ := writer.UpdatePrices(...)` then `writer.GetTransactionStatus(ctx, txID)`. See `integration/pkg/pricereader/fee_quoter_writer.go`.

### Idempotency key is set on every transaction

`EVMFeeQuoterWriter` now sets a fresh UUID as `txmgr.TxRequest.IdempotencyKey` on each `updatePrices` transaction. The TXM does not generate a key itself, and `GetTransactionStatus` looks transactions up by it. The same value is returned from `UpdatePrices` and logged as `txm key`. Each call uses a new key, so a later update is never dropped as a duplicate of an earlier one.

## References

- Prior changelog entries this builds on: none.
