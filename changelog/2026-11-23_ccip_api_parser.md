# CCIPApiParser on chain accessors

## Executive Summary

- Adds `chainaccess.CCIPApiParser`, which parses chain-specific values in CCIP API results, and `Accessor.CCIPApiParser()` to get it.
- Lets callers turn a CCIP API address string into a chain's native address bytes without branching on the chain family.
- Affects every implementer of `chainaccess.Accessor`; the EVM accessor is updated.
- Breaking for out-of-tree `Accessor` implementations: they must add the new method.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `chainaccess.Accessor.CCIPApiParser` | signature-changed | `chainaccess\.Accessor\b`, `\) GasPriceReader\(\) \(` | `pkg/chainaccess/interfaces.go:210` | [#accessor-gains-a-method](#accessor-gains-a-method) |
| `chainaccess.CCIPApiParser` | added | `CCIPApiParser\b` | `pkg/chainaccess/interfaces.go:187` | [#new-types](#new-types) |
| `evm.NewCCIPApiParser` | added | `NewCCIPApiParser\b` | `integration/pkg/accessors/evm/ccip_api_parser.go:19` | [#new-types](#new-types) |

## Breaking Changes

### Accessor gains a method

- **What changed:** `chainaccess.Accessor` has a new method `CCIPApiParser() (CCIPApiParser, error)`.
- **Before:** `Accessor` had no way to parse CCIP API values.
- **After:** every `Accessor` implementation must provide the method. It returns an error if the chain does not support it.
- **Why:** the CCIP API returns addresses as strings, and their format depends on the chain family.
- **Who is affected:** any code outside this repo that implements `chainaccess.Accessor`, including test fakes that do not embed it, and mocks generated from it.

## Migration Guide

1. Add the method to each `Accessor` implementation. A chain without support can return an error:

```go
func (a *myAccessor) CCIPApiParser() (chainaccess.CCIPApiParser, error) {
	return nil, errors.New("ccip api parser not available")
}
```

2. Regenerate mocks if you generate them from `Accessor`.

## New Features / Additions

### New types

- **`chainaccess.CCIPApiParser`** has one method, `DecodeAddress(address string) (protocol.UnknownAddress, error)`. It returns an error if the string is not a valid address for the chain.
- **Separate from `CCTPCodec`:** a chain family may not support CCTP, so it can implement `CCIPApiParser` without implementing `CCTPCodec`.
- **EVM implementation** (`evm.NewCCIPApiParser`, also returned by the EVM accessor's `CCIPApiParser()`): parses hex addresses, with or without `0x`, and requires exactly 20 bytes. Empty, non-hex, short and 32-byte padded inputs are errors.

Usage:

```go
parser, err := accessor.CCIPApiParser()
if err != nil { /* chain not supported */ }
addr, err := parser.DecodeAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
```
