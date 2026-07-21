# Narrower V3 message interfaces for devenv chain families

## Executive Summary

- `tcapi.SendV3Message` no longer requires a full `cciptestinterfaces.CCIP17` implementation for its `src`/`dst` parameters; it now takes the narrow `cciptestinterfaces.V3Source` and `cciptestinterfaces.V3Destination` interfaces directly, and derives the destination chain selector from `dst.ChainSelector()` instead of taking it as a separate `destSelector` parameter. The rest of the `tcapi` V3 test cases (send/confirm/balance/max-data-size assertions) have also been migrated off full `CCIP17` onto `V3Source`/`V3Destination` plus a set of small, standalone optional capability interfaces — the `build/devenv/tests/e2e/tcapi` package (and its `testutils/tokenpool` consumer) no longer references `cciptestinterfaces.CCIP17` anywhere except the unavoidable `ChainsMap` method a `ccv.Lib` implementation must still provide for other, non-`tcapi` consumers.
- This was made to remove friction for chain families that only want to run V3 message tests: previously they had to implement all 13 methods of `Chain`+`Observable` just to satisfy internal type assertions and direct method calls scattered across `tcapi`'s test cases, even though only a handful of those methods were ever used per role (source vs. destination). `V3Source`/`V3Destination` deliberately only bundle the capabilities *every* V3 test case needs (build/send/confirm a message); capabilities only specific test cases need (token balance reads, sender address, max data size) are kept as separate optional interfaces, type-asserted where used with a graceful skip/error — so a family isn't forced to implement, say, token-balance reporting just to run the basic send/confirm tests.
- Affects `build/devenv/cciptestinterfaces`, `build/devenv/chainreg`, `build/devenv` (`Lib`), `build/devenv/tests/e2e/tcapi`, `build/devenv/tests/e2e/testutils/tokenpool`, `build/devenv/tests/e2e` (`smoke_replay_cli_test.go`), and `build/devenv/evm`.
- Introduces a breaking change to `tcapi.SendV3Message`'s signature, to the `ccv.Lib` interface (two new required methods, one renamed), and to `tcapi.NewTestingContext`'s signature (dropped an unused parameter); everything else is additive and optional. Existing chain families (EVM, and the extra-args-only Canton/Solana stubs) continue to work unchanged via a fallback path.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `tcapi.SendV3Message` | signature-changed | `\.SendV3Message\(` | `build/devenv/tests/e2e/tcapi/types.go:87` | [#sendv3message-signature](#sendv3message-signature) |
| `tcapi.NewTestingContext` | signature-changed | `tcapi\.NewTestingContext\(` | `build/devenv/tests/e2e/tcapi/types.go:128` | [#newtestingcontext-drops-unused-impl-parameter](#newtestingcontext-drops-unused-impl-parameter) |
| `ccv.Lib` | signature-changed | `ccv\.Lib\b` | `build/devenv/lib.go:41` | [#lib-gains-v3-lookup-methods](#lib-gains-v3-lookup-methods) |
| `ccv.Lib.MessageV3Destination → ccv.Lib.V3Destination` | renamed | `\.MessageV3Destination\(` | `build/devenv/lib.go:81` | [#lib-v3destination-renamed](#lib-v3destination-renamed) |
| `cciptestinterfaces.V3Source` | added | `cciptestinterfaces\.V3Source\b` | `build/devenv/cciptestinterfaces/extra_args.go:63` | [#v3source-interface-added](#v3source-interface-added) |
| `cciptestinterfaces.V3Destination` | added | `cciptestinterfaces\.V3Destination\b` | `build/devenv/cciptestinterfaces/extra_args.go:71` | [#v3destination-interface-added](#v3destination-interface-added) |
| `cciptestinterfaces.TokenBalanceReader` | added | `cciptestinterfaces\.TokenBalanceReader\b` | `build/devenv/cciptestinterfaces/interface.go:383` | [#tokenbalancereader-and-senderaddressprovider-added](#tokenbalancereader-and-senderaddressprovider-added) |
| `cciptestinterfaces.SenderAddressProvider` | added | `cciptestinterfaces\.SenderAddressProvider\b` | `build/devenv/cciptestinterfaces/interface.go:390` | [#tokenbalancereader-and-senderaddressprovider-added](#tokenbalancereader-and-senderaddressprovider-added) |
| `cciptestinterfaces.MaxDataSizeProvider` | added | `cciptestinterfaces\.MaxDataSizeProvider\b` | `build/devenv/cciptestinterfaces/interface.go:397` | [#maxdatasizeprovider-added](#maxdatasizeprovider-added) |
| `chainreg.Registration.V3SourceFactory` / `.V3DestinationFactory` | added | `V3SourceFactory\|V3DestinationFactory` | `build/devenv/chainreg/types.go:163-164` | [#chainreg-v3-factories-added](#chainreg-v3-factories-added) |
| `evm.NewV3Source` / `evm.NewV3Destination` | added | `evm\.NewV3(Source\|Destination)\b` | `build/devenv/evm/registration.go:165,176` | [#evm-reference-registration](#evm-reference-registration) |

## Breaking Changes

### SendV3Message signature

- **What changed:** `tcapi.SendV3Message`'s `src`/`dst` parameter types, and the removal of its separate `destSelector` parameter.
- **Before:** `SendV3Message(ctx, src, dst cciptestinterfaces.CCIP17, destSelector uint64, ...)`, with internal type assertions to `ChainAsSource`, `MessageV3Source`, and `MessageV3Destination` that returned an error if any failed. An intermediate version of this change narrowed `dst` to `cciptestinterfaces.MessageV3Destination` while still taking `destSelector` separately.
- **After:** `SendV3Message(ctx, src cciptestinterfaces.V3Source, dst cciptestinterfaces.V3Destination, fields, opts, sendArgs)` — no `destSelector` parameter; the destination chain selector used internally for `SendChainMessage` is now derived from `dst.ChainSelector()` (available via `ChainAsDestination`, which `V3Destination` embeds).
- **Why:** Passing both `dst` and a separate `destSelector` meant two values had to agree on which chain was meant, with nothing enforcing that; every caller already resolves a full `v3Dst V3Destination` (via `Lib.V3Destination`) before calling `SendV3Message`, since they need it afterward for `ConfirmExecOnDest` anyway, so accepting `V3Destination` here costs callers nothing while letting the function derive the selector itself instead of trusting a second, possibly-mismatched argument.
- **Who is affected:** All 3 in-repo call sites (`build/devenv/tests/e2e/tcapi/basic/v3.go`, `build/devenv/tests/e2e/tcapi/token_transfer/v3.go`, `build/devenv/tests/e2e/testutils/tokenpool/token_transfer.go`) were updated to resolve `src`/`dst` via the new `Lib.V3Source`/`Lib.V3Destination` methods and to drop the now-redundant `destSelector`/`tc.dst`/`dstSel` argument from the call.

### NewTestingContext drops unused impl parameter

- **What changed:** `tcapi.NewTestingContext`'s parameter list and `tcapi.TestingContext`'s fields.
- **Before:** `NewTestingContext(ctx context.Context, impl map[uint64]cciptestinterfaces.CCIP17, aggregatorClient *ccv.AggregatorClient, indexerClient *ccv.IndexerMonitor) (TestingContext, func())`, with `TestingContext.Impl map[uint64]cciptestinterfaces.CCIP17` stored from `impl`.
- **After:** `NewTestingContext(ctx context.Context, aggregatorClient *ccv.AggregatorClient, indexerClient *ccv.IndexerMonitor) (TestingContext, func())`. The `Impl` field and `impl` parameter are gone.
- **Why:** `TestingContext.Impl` was never read anywhere in `tcapi` (not even by `AssertMessage`, which only uses `LogAsserter`/`AggregatorClient`/`IndexerClient`) or by any of its 4 call sites. It was dead weight that forced every caller to fetch a full `ChainsMap()` result for no reason — the last remaining reason any `tcapi` call site needed a `cciptestinterfaces.CCIP17`-typed value at all.
- **Who is affected:** All 4 call sites (`build/devenv/tests/e2e/tcapi/basic/v3.go`, `build/devenv/tests/e2e/tcapi/token_transfer/v3.go`, `build/devenv/tests/e2e/testutils/tokenpool/token_transfer.go`, `build/devenv/tests/e2e/smoke_replay_cli_test.go`) were updated to drop the `chainMap`/`impl` argument; the now-unnecessary `lib.ChainsMap(ctx)` call was removed from each. Note `smoke_replay_cli_test.go` lives outside `tcapi` (in `package e2e`, exercising the deprecated v1/v2 `SendMessage` path) but calls `tcapi.NewTestingContext` directly, so it also needed updating.

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
res, err := tcapi.SendV3Message(ctx, v3Src, v3Dst, fields, opts, sendArgs) // no destSelector — derived from v3Dst.ChainSelector()
```

2. If your test case also needs `ConfirmExecOnDest`, `GetEOAReceiverAddress`, or `ConfirmSendOnSource` — capabilities bundled directly into `V3Source`/`V3Destination` via `ChainAsSource`/`ChainAsDestination` — call them directly on the same `v3Src`/`v3Dst` values obtained above, no separate `ChainsMap()`-based lookup needed:

```go
// Before
chainMap, _ := lib.ChainsMap(ctx)
dst := chainMap[dstSelector]
evt, err := dst.ConfirmExecOnDest(ctx, srcSelector, key, timeout)
```

```go
// After
v3Dst, err := lib.V3Destination(ctx, dstSelector)
evt, err := v3Dst.ConfirmExecOnDest(ctx, srcSelector, key, timeout)
```

If your test case needs `GetTokenBalance`, `GetSenderAddress`, or `GetMaxDataBytes` — capabilities kept as separate optional interfaces, not bundled into `V3Source`/`V3Destination` (see New Features below for why) — type-assert down to the specific capability interface and handle the not-supported case explicitly (fail the test case, or skip it via `HavePrerequisites`/hydrate, depending on whether the capability is expected to be universally available in your context):

```go
// Before
chainMap, _ := lib.ChainsMap(ctx)
src, dst := chainMap[srcSelector], chainMap[dstSelector]
bal, err := dst.GetTokenBalance(ctx, receiver, token)
```

```go
// After
v3Dst, err := lib.V3Destination(ctx, dstSelector)
dstBalReader, ok := v3Dst.(cciptestinterfaces.TokenBalanceReader)
if !ok {
    return fmt.Errorf("destination chain %d does not support token balance reads", dstSelector)
}
bal, err := dstBalReader.GetTokenBalance(ctx, receiver, token)
```

3. If you implement `ccv.Lib` outside this repo, add `V3Source` and `V3Destination` methods (the latter replacing any prior `MessageV3Destination` method if you had already adopted an earlier version of this change). The simplest correct implementation, if your backend already exposes a `ChainsMap`-style method, is to assert the returned value against `cciptestinterfaces.V3Source`/`V3Destination` directly (see `libFromCLDF.V3Source`/`.V3Destination` in `build/devenv/lib.go:288,314` for the reference implementation, including the `chainreg` factory-lookup-first logic).
4. If you call `tcapi.NewTestingContext` directly, drop the `impl`/`chainMap` argument (and the `lib.ChainsMap(ctx)` call that produced it, if nothing else in your code used it):

```go
// Before
chainMap, _ := lib.ChainsMap(ctx)
testCtx, cleanup := tcapi.NewTestingContext(ctx, chainMap, aggregatorClient, indexerMonitor)
```

```go
// After
testCtx, cleanup := tcapi.NewTestingContext(ctx, aggregatorClient, indexerMonitor)
```

5. No action is required for existing chain families (EVM, and the extra-args-only Canton/Solana registrations) — the fallback path in `Lib.V3Source`/`Lib.V3Destination` preserves current behavior exactly.

## New Features / Additions

### Design principle: universal vs. per-test-case capabilities

`V3Source`/`V3Destination` only bundle capabilities *every* V3 test case needs — build/send/confirm a message. Capabilities only *some* test cases need (token balance reads, sender address, max data size) are deliberately kept as separate, single-method optional interfaces (`TokenBalanceReader`, `SenderAddressProvider`, `MaxDataSizeProvider`), type-asserted at the specific call site that needs them, mirroring the pre-existing `ProgressableChain`/`ReorgableChain`/`TokenConfigProvider` pattern in this package. An earlier iteration of this change bundled all of them into `V3Source`/`V3Destination`, which was reverted: it would have forced a family that only wants to run the basic send/confirm tests to also implement token-balance and sender-address reporting just to satisfy the compound interface, even though those methods are never called outside the token-transfer test suite. Follow-up quickstart documentation for `tcapi` (tracked separately, not part of this change) is expected to explain which optional interfaces each test case needs.

### V3Source interface added

**`cciptestinterfaces.V3Source`** (`build/devenv/cciptestinterfaces/extra_args.go:63`) — compound interface (`MessageV3Source` + `ChainAsSource`) used by `SendV3Message`'s `src` parameter and by the new `chainreg.V3SourceFactory`/`Lib.V3Source`. Covers only what every source-role V3 test case needs: build/send/confirm the message. Test cases needing more (e.g. token balance, sender address) type-assert the returned value further — see "Design principle" above.

### V3Destination interface added

**`cciptestinterfaces.V3Destination`** (`build/devenv/cciptestinterfaces/extra_args.go:71`) — compound interface (`MessageV3Destination` + `ChainAsDestination`) used by `Lib.V3Destination` and `chainreg.V3DestinationFactory`. `ChainAsDestination` (pre-existing) already bundles `ConfirmExecOnDest`/`GetEOAReceiverAddress`/`ChainSelector` — the capabilities every destination-role V3 test case needs. Test cases needing more (token balance, max data size) type-assert further — see "Design principle" above.

### TokenBalanceReader and SenderAddressProvider added

**`cciptestinterfaces.TokenBalanceReader`** (`build/devenv/cciptestinterfaces/interface.go:383`, `GetTokenBalance`) and **`cciptestinterfaces.SenderAddressProvider`** (`interface.go:390`, `GetSenderAddress`) — two new single-method marker interfaces, factored out of the full `Chain` interface (which now embeds both, so existing full-`CCIP17` implementations like EVM automatically satisfy them). Neither is embedded in `V3Source`/`V3Destination` (see "Design principle" above) — they're type-asserted where needed. `TokenBalanceReader` applies identically to a source chain (checking the sender's balance) or a destination chain (checking the receiver's balance); it's asserted in `build/devenv/tests/e2e/tcapi/token_transfer/v3.go` and `build/devenv/tests/e2e/testutils/tokenpool/token_transfer.go`, both on `v3Src` and `v3Dst`. `SenderAddressProvider` is source-specific and is asserted only where a source's sender address is needed (the same two files' hydrate paths); the destination-side equivalent, `GetEOAReceiverAddress`, is universal enough that it stays bundled in `ChainAsDestination`.

### MaxDataSizeProvider added

**`cciptestinterfaces.MaxDataSizeProvider`** (`build/devenv/cciptestinterfaces/interface.go:397`, `GetMaxDataBytes`) — another single-method marker interface factored out of `Chain` (which now embeds it). Not embedded in `V3Destination` — it's asserted only where used. `GetMaxDataBytes` is asked of the chain *receiving* a message (its only in-repo call site, `build/devenv/tests/e2e/tcapi/basic/v3.go`'s `maxDataSize` test case, invokes it on the destination chain via `env.Dst.(cciptestinterfaces.MaxDataSizeProvider)`, skipping the test case via its hydrate function returning `false` if unsupported), so — like `SenderAddressProvider` — it's single-role and single-test-case, not shared with `V3Source`. This closed the last capability gap that forced `tcapi/basic/v3.go`'s `loadV3Env`/`v3Env.Dst` to fetch a full `CCIP17` value via `ChainsMap`; `v3Env.Dst` is now typed `cciptestinterfaces.V3Destination` and resolved via `Lib.V3Destination`, with the `maxDataSize`-specific capability asserted separately.

### chainreg V3 factories added

**`chainreg.Registration.V3SourceFactory` / `.V3DestinationFactory`** — two new optional fields (`build/devenv/chainreg/types.go:163-164`) that let a chain family register support for V3 message send/receive without implementing the full `chainreg.ImplFactory`/`cciptestinterfaces.CCIP17` surface (which also pulls in unrelated deployment/funding-bootstrap concerns: `NewEmpty`, `DefaultSignerKey`, `DefaultFeeAggregator`, `SupportsFunding`).

- Usage: a family that can only send V3 messages sets `V3SourceFactory` alone; a family that can only receive sets `V3DestinationFactory` alone; both are independently optional, matching the existing `ChainAsSource`/`ChainAsDestination` interface split. Each factory has the same signature shape as `ImplFactory.New`: `func(ctx context.Context, lggr zerolog.Logger, env *deployment.Environment, chainSelector uint64) (<narrow interface>, error)`.

### EVM reference registration

**`evm.NewV3Source` / `evm.NewV3Destination`** (`build/devenv/evm/registration.go:165,176`) — EVM's registration of the two new factories, serving as the reference implementation for other families (Solana, Canton, etc.) to copy. Both simply delegate to the existing `NewCCIP17EVM` constructor, since `*CCIP17EVM` already satisfies both narrow interfaces; a family that hasn't fully implemented `CCIP17` need only return a value satisfying the relevant narrow interface here.

## References

- Prior changelog entries this builds on: none.
