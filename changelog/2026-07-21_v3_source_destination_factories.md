# Narrower V3 message interfaces for devenv chain families

## Executive Summary

- `tcapi.SendV3Message` no longer requires a full `cciptestinterfaces.CCIP17` implementation for its `src`/`dst` parameters; it now takes the narrow `cciptestinterfaces.V3Source` and `cciptestinterfaces.MessageV3Destination` interfaces directly. The rest of the `tcapi` V3 test cases (send/confirm/balance assertions) have also been migrated off full `CCIP17` onto two new compound interfaces, `V3Source` and `V3Destination`.
- This was made to remove friction for chain families that only want to run V3 message tests: previously they had to implement all 13 methods of `Chain`+`Observable` just to satisfy internal type assertions and direct method calls scattered across `tcapi`'s test cases, even though only a handful of those methods were ever used per role (source vs. destination).
- Affects `build/devenv/cciptestinterfaces`, `build/devenv/chainreg`, `build/devenv` (`Lib`), `build/devenv/tests/e2e/tcapi`, `build/devenv/tests/e2e/testutils/tokenpool`, and `build/devenv/evm`.
- Introduces a breaking change to `tcapi.SendV3Message`'s signature and to the `ccv.Lib` interface (two new required methods, one renamed); everything else is additive and optional. Existing chain families (EVM, and the extra-args-only Canton/Solana stubs) continue to work unchanged via a fallback path.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `tcapi.SendV3Message` | signature-changed | `\.SendV3Message\(` | `build/devenv/tests/e2e/tcapi/types.go:87` | [#sendv3message-signature](#sendv3message-signature) |
| `ccv.Lib.MessageV3Destination → ccv.Lib.V3Destination` | renamed | `\.MessageV3Destination\(` | `build/devenv/lib.go:81` | [#lib-v3destination-renamed](#lib-v3destination-renamed) |
| `ccv.Lib` | signature-changed | `ccv\.Lib\b` | `build/devenv/lib.go:41` | [#lib-gains-v3-lookup-methods](#lib-gains-v3-lookup-methods) |
| `cciptestinterfaces.V3Source` | added | `cciptestinterfaces\.V3Source\b` | `build/devenv/cciptestinterfaces/extra_args.go:63` | [#v3source-interface-added](#v3source-interface-added) |
| `cciptestinterfaces.V3Destination` | added | `cciptestinterfaces\.V3Destination\b` | `build/devenv/cciptestinterfaces/extra_args.go:71` | [#v3destination-interface-added](#v3destination-interface-added) |
| `cciptestinterfaces.TokenBalanceReader` | added | `cciptestinterfaces\.TokenBalanceReader\b` | `build/devenv/cciptestinterfaces/interface.go:383` | [#tokenbalancereader-and-senderaddressprovider-added](#tokenbalancereader-and-senderaddressprovider-added) |
| `cciptestinterfaces.SenderAddressProvider` | added | `cciptestinterfaces\.SenderAddressProvider\b` | `build/devenv/cciptestinterfaces/interface.go:390` | [#tokenbalancereader-and-senderaddressprovider-added](#tokenbalancereader-and-senderaddressprovider-added) |
| `chainreg.Registration.V3SourceFactory` / `.V3DestinationFactory` | added | `V3SourceFactory\|V3DestinationFactory` | `build/devenv/chainreg/types.go:163-164` | [#chainreg-v3-factories-added](#chainreg-v3-factories-added) |
| `evm.NewV3Source` / `evm.NewV3Destination` | added | `evm\.NewV3(Source\|Destination)\b` | `build/devenv/evm/registration.go:165,176` | [#evm-reference-registration](#evm-reference-registration) |

## Breaking Changes

### SendV3Message signature

- **What changed:** `tcapi.SendV3Message`'s `src`/`dst` parameter types.
- **Before:** `SendV3Message(ctx, src, dst cciptestinterfaces.CCIP17, destSelector uint64, ...)`, with internal type assertions to `ChainAsSource`, `MessageV3Source`, and `MessageV3Destination` that returned an error if any failed.
- **After:** `SendV3Message(ctx, src cciptestinterfaces.V3Source, dst cciptestinterfaces.MessageV3Destination, destSelector uint64, ...)`. `V3Source` is a new compound interface embedding `MessageV3Source`, `ChainAsSource`, `TokenBalanceReader`, and `SenderAddressProvider`. No internal assertions remain — the compiler enforces the requirement at the call site instead.
- **Why:** The function only ever used a handful of methods (`BuildChainMessage`, `SendChainMessage`, `ConfirmSendOnSource` via `ChainAsSource`; `BuildV3ExtraArgs` via `MessageV3Source`; `GetExecutorArgs`/`GetTokenReceiver`/`GetTokenArgs` via `MessageV3Destination`), not the full 13-method `CCIP17` surface. `dst`'s param type stays the minimal `MessageV3Destination` (not the richer `V3Destination`) since `SendV3Message` itself never calls `ConfirmExecOnDest`/`GetTokenBalance` — callers needing those resolve a `V3Destination` separately via `Lib.V3Destination` and pass it in, since `V3Destination`'s method set is a superset that satisfies `MessageV3Destination` automatically.
- **Who is affected:** All 3 in-repo call sites (`build/devenv/tests/e2e/tcapi/basic/v3.go`, `build/devenv/tests/e2e/tcapi/token_transfer/v3.go`, `build/devenv/tests/e2e/testutils/tokenpool/token_transfer.go`) were updated to resolve `src`/`dst` via the new `Lib.V3Source`/`Lib.V3Destination` methods instead of asserting a `CCIP17`-typed value directly.

### Lib.V3Destination renamed

- **What changed:** `ccv.Lib`'s destination-side V3 lookup method.
- **Before:** `Lib.MessageV3Destination(ctx, chainSelector) (cciptestinterfaces.MessageV3Destination, error)`.
- **After:** `Lib.V3Destination(ctx, chainSelector) (cciptestinterfaces.V3Destination, error)`.
- **Why:** `tcapi`'s V3 test cases call `ConfirmExecOnDest` and `GetTokenBalance` directly on the destination chain in addition to building extra args — neither method exists on `MessageV3Destination` alone. Rather than keep two separate `Lib` lookups (one for message-building, one for confirmation/balance checks), the method now returns the richer `V3Destination` compound type in one call; since `V3Destination` embeds `MessageV3Destination`, the same value still satisfies `SendV3Message`'s `dst` parameter with no extra work at call sites.
- **Who is affected:** Any external implementer of `ccv.Lib` that had already added `MessageV3Destination` under the prior (never-released) shape of this change must rename it to `V3Destination` and widen the return type.

### Lib gains V3 lookup methods

- **What changed:** The `ccv.Lib` interface (`build/devenv/lib.go:41`).
- **Before:** `Lib` exposed `Chains`, `ChainsMap`, `CLDFEnvironment`, `DataStore`, `Indexer`, `IndexerMonitor`, `AllIndexers`, `AllAggregators`.
- **After:** `Lib` additionally requires `V3Source(ctx context.Context, chainSelector uint64) (cciptestinterfaces.V3Source, error)` and `V3Destination(ctx context.Context, chainSelector uint64) (cciptestinterfaces.V3Destination, error)`.
- **Why:** These methods are the single place that resolves a chain's V3 send/receive capability: they check `chainreg`'s registry for a family-specific `V3SourceFactory`/`V3DestinationFactory` first, and fall back to asserting the existing `ChainsMap()`-sourced `CCIP17` value if no factory is registered. Centralizing this in `Lib` (rather than duplicating it at each `tcapi` call site) mirrors how `Lib.ChainsMap` already invokes `chainreg.ImplFactory.New`.
- **Who is affected:** Any external implementer of `ccv.Lib` must add these two methods. `libFromCCV` delegates to `libFromCLDF`, matching the existing `ChainsMap`/`Chains` delegation pattern. The in-repo test double `stubLib` (`build/devenv/tests/e2e/tcapi/offchain_test.go`) was updated to return `(nil, nil)` for both.

## Migration Guide

1. If you call `tcapi.SendV3Message` directly with `cciptestinterfaces.CCIP17`-typed variables, resolve `src`/`dst` through the new `Lib` methods first instead of indexing a `ChainsMap()` result directly:

```go
// Before
chainMap, _ := lib.ChainsMap(ctx)
src := chainMap[srcSelector]
dst := chainMap[dstSelector]
res, err := tcapi.SendV3Message(ctx, src, dst, dstSelector, fields, opts, sendArgs)
```

```go
// After
v3Src, err := lib.V3Source(ctx, srcSelector)
v3Dst, err := lib.V3Destination(ctx, dstSelector)
res, err := tcapi.SendV3Message(ctx, v3Src, v3Dst, dstSelector, fields, opts, sendArgs)
```

2. If your test case also needs `ConfirmExecOnDest`, `GetTokenBalance`, `GetEOAReceiverAddress`, `ConfirmSendOnSource`, or `GetSenderAddress` (typical for asserting a message landed and balances moved), call them directly on the same `v3Src`/`v3Dst` values obtained above — no separate `ChainsMap()`-based lookup is needed:

```go
// Before
chainMap, _ := lib.ChainsMap(ctx)
src, dst := chainMap[srcSelector], chainMap[dstSelector]
bal, err := dst.GetTokenBalance(ctx, receiver, token)
...
evt, err := dst.ConfirmExecOnDest(ctx, srcSelector, key, timeout)
```

```go
// After
v3Src, err := lib.V3Source(ctx, srcSelector)
v3Dst, err := lib.V3Destination(ctx, dstSelector)
bal, err := v3Dst.GetTokenBalance(ctx, receiver, token)
...
evt, err := v3Dst.ConfirmExecOnDest(ctx, srcSelector, key, timeout)
```

3. If you implement `ccv.Lib` outside this repo, add `V3Source` and `V3Destination` methods (the latter replacing any prior `MessageV3Destination` method if you had already adopted an earlier version of this change). The simplest correct implementation, if your backend already exposes a `ChainsMap`-style method, is to assert the returned value against `cciptestinterfaces.V3Source`/`V3Destination` directly (see `libFromCLDF.V3Source`/`.V3Destination` in `build/devenv/lib.go:288,314` for the reference implementation, including the `chainreg` factory-lookup-first logic).
4. No action is required for existing chain families (EVM, and the extra-args-only Canton/Solana registrations) — the fallback path in `Lib.V3Source`/`Lib.V3Destination` preserves current behavior exactly.

## New Features / Additions

### V3Source interface added

**`cciptestinterfaces.V3Source`** (`build/devenv/cciptestinterfaces/extra_args.go:63`) — compound interface (`MessageV3Source` + `ChainAsSource` + `TokenBalanceReader` + `SenderAddressProvider`) used by `SendV3Message`'s `src` parameter and by the new `chainreg.V3SourceFactory`/`Lib.V3Source`. Covers everything a source-role chain needs in a V3 test case: build/send/confirm the message, plus report its own token balance and sender address for pre/post assertions.

### V3Destination interface added

**`cciptestinterfaces.V3Destination`** (`build/devenv/cciptestinterfaces/extra_args.go:71`) — compound interface (`MessageV3Destination` + `ChainAsDestination` + `TokenBalanceReader`) used by `Lib.V3Destination` and `chainreg.V3DestinationFactory`. `ChainAsDestination` (pre-existing) already bundled `ConfirmExecOnDest`/`GetEOAReceiverAddress`/`ChainSelector`; `V3Destination` adds `TokenBalanceReader` on top so destination-role balance assertions no longer need a full `CCIP17` value either.

### TokenBalanceReader and SenderAddressProvider added

**`cciptestinterfaces.TokenBalanceReader`** (`build/devenv/cciptestinterfaces/interface.go:383`, `GetTokenBalance`) and **`cciptestinterfaces.SenderAddressProvider`** (`interface.go:390`, `GetSenderAddress`) — two new single-method marker interfaces, factored out of the full `Chain` interface (which now embeds both). `TokenBalanceReader` applies identically to a source chain (checking the sender's balance) or a destination chain (checking the receiver's balance) — both `V3Source` and `V3Destination` embed it. `SenderAddressProvider` is source-specific and is embedded only in `V3Source` (the destination-side equivalent, `GetEOAReceiverAddress`, already lived on `ChainAsDestination`).

### chainreg V3 factories added

**`chainreg.Registration.V3SourceFactory` / `.V3DestinationFactory`** — two new optional fields (`build/devenv/chainreg/types.go:163-164`) that let a chain family register support for V3 message send/receive without implementing the full `chainreg.ImplFactory`/`cciptestinterfaces.CCIP17` surface (which also pulls in unrelated deployment/funding-bootstrap concerns: `NewEmpty`, `DefaultSignerKey`, `DefaultFeeAggregator`, `SupportsFunding`).

- Usage: a family that can only send V3 messages sets `V3SourceFactory` alone; a family that can only receive sets `V3DestinationFactory` alone; both are independently optional, matching the existing `ChainAsSource`/`ChainAsDestination` interface split. Each factory has the same signature shape as `ImplFactory.New`: `func(ctx context.Context, lggr zerolog.Logger, env *deployment.Environment, chainSelector uint64) (<narrow interface>, error)`.

### EVM reference registration

**`evm.NewV3Source` / `evm.NewV3Destination`** (`build/devenv/evm/registration.go:165,176`) — EVM's registration of the two new factories, serving as the reference implementation for other families (Solana, Canton, etc.) to copy. Both simply delegate to the existing `NewCCIP17EVM` constructor, since `*CCIP17EVM` already satisfies both narrow interfaces; a family that hasn't fully implemented `CCIP17` need only return a value satisfying the relevant narrow interface here.

## References

- Prior changelog entries this builds on: none.
