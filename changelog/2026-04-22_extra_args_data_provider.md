# Chain-agnostic extra args via `ExtraArgsDataProvider` and functional-option `ExtraArgsBuilder`

## Executive Summary

- Replaces the EVM-leaning `MessageOptions` surface on `Chain` / `ChainAsSource` with a marker interface `ExtraArgsDataProvider` and a per-family builder method `ChainAsDestination.ExtraArgsBuilder(opts ...ExtraArgsOption)`.
- Motivated by adding Solana (`SVMMessageOptions`) support: source chains can no longer assume the extra-args struct is EVM-shaped, so serialization is now type-switched on the provider instead of a single registered serializer.
- Affects every implementor of `cciptestinterfaces.Chain`, `ChainAsSource`, `ChainAsDestination`, or `ChainSendOption`, plus every test or CLI that built a `MessageOptions` literal and passed it into `BuildChainMessage` / `SendMessage`.
- Breaking: `BuildChainMessage` now takes pre-serialized `extraArgs []byte`; `ChainSendOption.IsSendOption()` loses its `bool` return; `ExtraArgsSerializer` returns `(..., error)`; new required methods appear on `ChainAsDestination` and `ChainAsSource`.

## Breaking Changes

### `ChainAsDestination` gains `ExtraArgsBuilder`

- **What changed:** new required method on `cciptestinterfaces.ChainAsDestination`.
- **Before:** interface had no way for a destination chain to allocate its own extra-args shape.
- **After:**
  ```go
  ExtraArgsBuilder(opts ...ExtraArgsOption) (ExtraArgsDataProvider, error)
  ```
  The destination allocates its family-specific provider (e.g. `*MessageOptions` for EVM, `*SVMMessageOptions` for SVM) and applies each option; options that don't match the provider's concrete type return an error.
- **Why:** the destination chain is the only party that knows the shape of its extra args. Hoisting construction there lets generic tests stay agnostic.
- **Who is affected:** every `ChainAsDestination` implementation. Currently only `*evm.CCIP17EVM` at `build/devenv/evm/impl.go:2037`.

### `ChainAsSource.BuildChainMessage` takes serialized bytes

- **What changed:** `cciptestinterfaces.ChainAsSource.BuildChainMessage` signature.
- **Before:**
  ```go
  BuildChainMessage(ctx, destChain, fields MessageFields, opts MessageOptions) (ChainAsSourceMessage, error)
  ```
- **After:**
  ```go
  BuildChainMessage(ctx, destChain, fields MessageFields, extraArgs []byte) (GenericChainMessage, error)
  ```
  The caller is expected to serialize extra args via `ChainAsSource.SerializeExtraArgs(provider)` first.
- **Why:** the source shouldn't know about destination-specific option structs; it only needs the opaque byte blob to stuff into the on-chain message.
- **Who is affected:** every `ChainAsSource` implementor and every caller (`tests/composable/messaging/agnostic_chain_test.go:16`, `tests/e2e/gun.go:206`).

### `ChainAsSource` gains `SerializeExtraArgs`

- **What changed:** new required method.
- **After:**
  ```go
  SerializeExtraArgs(ExtraArgsDataProvider) ([]byte, error)
  ```
  Implementations type-switch on the provider (see `*evm.CCIP17EVM.SerializeExtraArgs` at `build/devenv/evm/impl.go:687`, which dispatches to `SerializeEVMExtraArgs` or `SerializeSVMExtraArgs`).
- **Why:** replaces the single-serializer-per-family registry (`RegisterExtraArgsSerializer`) with per-source dispatch, so one source chain can serialize to multiple destination families.

### `ChainSendOption.IsSendOption()` return type

- **What changed:** marker method signature.
- **Before:** `IsSendOption() bool`
- **After:** `IsSendOption()`
- **Why:** the returned bool was never inspected; it was pure boilerplate.
- **Who is affected:** every `ChainSendOption` implementor. `evm.SendOptions.IsSendOption` already updated at `build/devenv/evm/interface.go:38`.

### `ExtraArgsSerializer` signature

- **What changed:** registered-serializer type.
- **Before:** `type ExtraArgsSerializer func(opts MessageOptions) []byte`
- **After:** `type ExtraArgsSerializer func(provider ExtraArgsDataProvider) ([]byte, error)`
- **Why:** the serializer now receives the generic marker interface (so it can be invoked for SVM or EVM providers) and reports unsupported-type errors instead of panicking.
- **Who is affected:** any product repo that calls `cciptestinterfaces.RegisterExtraArgsSerializer`. The registry itself is retained at `build/devenv/cciptestinterfaces/interface.go:297` for backward usage.

### `Chain.SendMessage` opts parameter

- **What changed:** generic `Chain` interface.
- **Before:** `SendMessage(ctx, dest, fields, opts MessageOptions) (MessageSentEvent, error)`
- **After:** `SendMessage(ctx, dest, fields, dataProvider ExtraArgsDataProvider) (MessageSentEvent, error)`
- **Why:** same motivation — `MessageOptions` is no longer the only valid shape.
- **Who is affected:** callers passing `MessageOptions` literals keep working (the value still satisfies `ExtraArgsDataProvider`); callers that passed typed variables of exact type `cciptestinterfaces.MessageOptions` are unaffected.

### `ChainAsSourceMessage` renamed to `GenericChainMessage`

- **What changed:** type alias in `cciptestinterfaces`.
- **Before:** `type ChainAsSourceMessage any`
- **After:** `type GenericChainMessage any`
- **Why:** the type is also used as the input to `SendChainMessage`, so "as source" was misleading.
- **Who is affected:** any code that named the alias explicitly (tests typically let type inference handle it).

## Migration Guide

1. **Update `ChainAsSource` implementations:**
   - Change `BuildChainMessage` to accept `extraArgs []byte` and return `GenericChainMessage`.
   - Add a `SerializeExtraArgs(ExtraArgsDataProvider) ([]byte, error)` method that type-switches on the providers you support.
   - Change `SendChainMessage`'s `message` parameter type to `GenericChainMessage`.

2. **Update `ChainAsDestination` implementations:** add
   ```go
   func (c *YourChain) ExtraArgsBuilder(opts ...cciptestinterfaces.ExtraArgsOption) (cciptestinterfaces.ExtraArgsDataProvider, error) {
       p := &YourChainExtraArgs{}
       for _, opt := range opts {
           if err := opt(p); err != nil {
               return nil, err
           }
       }
       return *p, nil // or p, consistent with what SerializeExtraArgs expects
   }
   ```

3. **Update `ChainSendOption` implementations:** drop the `bool` return from `IsSendOption`:
   ```go
   // Before
   func (o SendOptions) IsSendOption() bool { return true }
   // After
   func (o SendOptions) IsSendOption() {}
   ```

4. **Update callers that built messages end-to-end:** serialize first, then build.
   ```go
   // Before
   msg, err := src.BuildChainMessage(ctx, destSel, fields, opts)

   // After
   extraArgs, err := src.SerializeExtraArgs(opts)
   if err != nil { /* handle */ }
   msg, err := src.BuildChainMessage(ctx, destSel, fields, extraArgs)
   ```

5. **Update generic scenario helpers to take options instead of a concrete struct** (see `tests/composable/messaging/agnostic_chain_test.go`):
   ```go
   // Before
   func BasicMessageTestScenario(..., opts cciptestinterfaces.MessageOptions, ...) error {
       srcMessage, err := srcChain.BuildChainMessage(ctx, destChain.ChainSelector(), fields, opts)
       ...
   }

   // After
   func BasicMessageTestScenario(..., extraArgsOptions []cciptestinterfaces.ExtraArgsOption, ...) error {
       provider, err := destChain.ExtraArgsBuilder(extraArgsOptions...)
       if err != nil { return fmt.Errorf("build extra args: %w", err) }
       extraArgs, err := srcChain.SerializeExtraArgs(provider)
       if err != nil { return fmt.Errorf("serialize extra args: %w", err) }
       srcMessage, err := srcChain.BuildChainMessage(ctx, destChain.ChainSelector(), fields, extraArgs)
       ...
   }
   ```

6. **Callers constructing `MessageOptions{...}` literals** do not need to change the literal — the struct still exists, just moved from `interface.go` to `extra_args.go` in the same package. `cciptestinterfaces.MessageOptions{...}` continues to satisfy `ExtraArgsDataProvider` and can be passed directly to `SendMessage` / `SerializeExtraArgs`.

## New Features / Additions

- **`cciptestinterfaces.ExtraArgsDataProvider`** — marker interface satisfied by any chain family's extra-args struct. See `build/devenv/cciptestinterfaces/interface.go:376`.
- **`cciptestinterfaces.ExtraArgsOption`** — `func(ExtraArgsDataProvider) error`. Option functions type-assert the provider to the concrete struct they target; mismatches return a typed error rather than silently no-op'ing. See `build/devenv/cciptestinterfaces/extra_args.go:14`.
- **`cciptestinterfaces.SVMMessageOptions`** — Solana-shaped extra args (ComputeUnits, AccountIsWritableBitmap, AllowOutOfOrderExecution, TokenReceiver, Accounts). See `build/devenv/cciptestinterfaces/extra_args.go:104`.
- **EVM option constructors** for mutating `*MessageOptions`: `WithVersion`, `WithExecutionGasLimit`, `WithOutOfOrderExecution`, `WithCCVs`, `WithFinalityConfig`, `WithExecutor`, `WithExecutorArgs`, `WithTokenArgs`, `WithUseTestRouter`. Defined in `build/devenv/cciptestinterfaces/extra_args.go:50`.
  - Usage: pass to `destChain.ExtraArgsBuilder(...)`. Errors from applying an option to a non-EVM provider carry the constructor name (e.g. `"evm.WithExecutionGasLimit: expected *MessageOptions (EVM family), got <T>"`).
- **`*evm.CCIP17EVM.SerializeExtraArgs`** — type-switches on `ExtraArgsDataProvider` and dispatches to `SerializeEVMExtraArgs` or `SerializeSVMExtraArgs`. Replaces the previous single `serializeExtraArgs` helper that looked up a serializer from the destination family registry.
- **`serializeExtraArgsSVMV1`** now consumes `SVMMessageOptions` fields directly (ComputeUnits, AccountIsWritableBitmap, TokenReceiver, Accounts) instead of reinterpreting EVM `MessageOptions` fields with SVM semantics. See `build/devenv/evm/impl.go:806`.

## Examples

Build and send a message to an EVM destination using the functional-options builder:

```go
provider, err := destChain.ExtraArgsBuilder(
    cciptestinterfaces.WithVersion(3),
    cciptestinterfaces.WithExecutionGasLimit(200_000),
    cciptestinterfaces.WithOutOfOrderExecution(false),
)
if err != nil { /* handle */ }

extraArgs, err := srcChain.SerializeExtraArgs(provider)
if err != nil { /* handle */ }

msg, err := srcChain.BuildChainMessage(ctx, destChain.ChainSelector(), fields, extraArgs)
```

Generic scenario helper — no destination-family knowledge required:

```go
BasicMessageTestScenario(ctx, t, srcChain, destChain, fields,
    []cciptestinterfaces.ExtraArgsOption{
        cciptestinterfaces.WithExecutionGasLimit(200_000),
        cciptestinterfaces.WithVersion(3),
        cciptestinterfaces.WithOutOfOrderExecution(false),
    },
    nil,
)
```

## References

- Prior changelog entries this builds on: `2026-04-20_composable_chain_interfaces.md` (introduced `ChainAsSource` / `ChainAsDestination` / `ChainSendOption`).
- Commits on `aw/extraArgInterfaces` vs `main`: `2ff7e6d2` (switch messageOptions to an interface), `d5ba454f` (bring extra args back to cciptestinterfaces, use optional interfaces for the extra args builder).
