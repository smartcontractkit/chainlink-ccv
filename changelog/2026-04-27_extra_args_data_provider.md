# Per-version extra-args data providers and pre-serialized extra args on `BuildChainMessage`

## Executive Summary

- Replaces the EVM-V3-shaped `cciptestinterfaces.MessageOptions` (with a `Version` field) with one `ExtraArgsDataProvider`-implementing struct per `(message version, destination family)` and switches the registry / source-chain plumbing to look up serializers by `(family, version)`.
- Motivated by adding non-EVM destinations (Solana) and non-V3 message versions: a single struct could not represent V1/V2/V3-EVM and V1-SVM extra args without overloading fields.
- Affects every implementor of `cciptestinterfaces.Chain`, `ChainAsSource`, `ChainSendOption`, and `ExtraArgsSerializer`, plus every test or CLI that built a `MessageOptions` literal — `MessageOptions.Version` and `MessageOptions.UseTestRouter` no longer exist.
- Breaking: `Chain.SendMessage` takes an `ExtraArgsDataProvider` plus a separate `messageVersion uint8` (and is now deprecated); `ChainAsSource.BuildChainMessage` drops the `destChain uint64` parameter and takes a pre-serialized `GenericExtraArgs` (alias for `[]byte`); `ChainSendOption.IsSendOption()` loses its `bool` return; `ExtraArgsSerializer` returns `(GenericExtraArgs, error)` and is keyed by `ExtraArgsSerializerEntry{Family, Version}`; `ChainAsSourceMessage` renamed to `GenericChainMessage`.

## AI Adapter Index

Read this table first. For each row, run the `Search` pattern against the consumer repo; if it produces hits, follow the linked `Section` for migration detail. Symbols not in this table are unchanged — do not load source for them. The `evm.*` and `messaging.*` rows live in this repo's `build/devenv/...` tree; downstream repos that vendor or shadow these packages should look in the corresponding paths.

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `cciptestinterfaces.MessageOptions.Version` | removed | `\bVersion:\s*\d` | — | [MessageOptions loses Version and UseTestRouter](#messageoptions-loses-version-and-usetestrouter) |
| `cciptestinterfaces.MessageOptions.UseTestRouter` | removed | `\bUseTestRouter\b` | — | [MessageOptions loses Version and UseTestRouter](#messageoptions-loses-version-and-usetestrouter) |
| `messaging.BasicMessageTestScenario` | removed | `\bBasicMessageTestScenario\b` | — | [Migration Guide step 7](#migration-guide) |
| `cciptestinterfaces.Chain.SendMessage` | signature-changed (and deprecated) | `\.SendMessage\(` | `build/devenv/cciptestinterfaces/interface.go:144` | [Chain.SendMessage signature](#chainsendmessage-signature) |
| `cciptestinterfaces.ChainAsSource.BuildChainMessage` | signature-changed | `\.BuildChainMessage\(` | `build/devenv/cciptestinterfaces/interface.go:415` | [ChainAsSource.BuildChainMessage takes serialized bytes](#chainassourcebuildchainmessage-takes-serialized-bytes) |
| `cciptestinterfaces.ChainSendOption.IsSendOption` | signature-changed | `\bIsSendOption\(\)` | `build/devenv/cciptestinterfaces/interface.go:379` | [ChainSendOption.IsSendOption() return type](#chainsendoptionissendoption-return-type) |
| `cciptestinterfaces.ExtraArgsSerializer` | signature-changed | `\bExtraArgsSerializer\b` | `build/devenv/cciptestinterfaces/interface.go:319` | [ExtraArgsSerializer signature and registry key](#extraargsserializer-signature-and-registry-key) |
| `cciptestinterfaces.RegisterExtraArgsSerializer` | signature-changed | `\bRegisterExtraArgsSerializer\(` | `build/devenv/cciptestinterfaces/interface.go:335` | [ExtraArgsSerializer signature and registry key](#extraargsserializer-signature-and-registry-key) |
| `cciptestinterfaces.GetExtraArgsSerializer` | signature-changed | `\bGetExtraArgsSerializer\(` | `build/devenv/cciptestinterfaces/interface.go:345` | [ExtraArgsSerializer signature and registry key](#extraargsserializer-signature-and-registry-key) |
| `evm.SerializeEVMExtraArgs` | signature-changed | `\bSerializeEVMExtraArgs\(` | `build/devenv/evm/impl.go:692` | [ExtraArgsSerializer signature and registry key](#extraargsserializer-signature-and-registry-key) |
| `cciptestinterfaces.ChainAsSourceMessage → cciptestinterfaces.GenericChainMessage` | renamed | `\bChainAsSourceMessage\b` | `build/devenv/cciptestinterfaces/interface.go:429` | [ChainAsSourceMessage renamed to GenericChainMessage](#chainassourcemessage-renamed-to-genericchainmessage) |
| `messaging.TestEVM2EVMPOC → messaging.TestEVM2EVMV3` | renamed | `\bTestEVM2EVMPOC\b` | `build/devenv/tests/composable/messaging/evmPOC_test.go:26` | [Migration Guide step 7](#migration-guide) |
| `cciptestinterfaces.ExtraArgsDataProvider` | added | — | `build/devenv/cciptestinterfaces/interface.go:386` | [New Features / Additions](#new-features--additions) |
| `cciptestinterfaces.ExtraArgsSerializerEntry` | added | — | `build/devenv/cciptestinterfaces/interface.go:326` | [ExtraArgsSerializer signature and registry key](#extraargsserializer-signature-and-registry-key) |
| `cciptestinterfaces.GenericExtraArgs` | added | `\bGenericExtraArgs\b` | `build/devenv/cciptestinterfaces/interface.go:432` | [New Features / Additions](#new-features--additions) |
| `cciptestinterfaces.MessageV3ExecutorArgs` / `MessageV3TokenArgs` | added | — | `build/devenv/cciptestinterfaces/extra_args.go:31` | [New Features / Additions](#new-features--additions) |
| `cciptestinterfaces.MessageV3Source` | added | — | `build/devenv/cciptestinterfaces/extra_args.go:49` | [New Features / Additions](#new-features--additions) |
| `cciptestinterfaces.MessageV3Destination` | added | — | `build/devenv/cciptestinterfaces/extra_args.go:38` | [New Features / Additions](#new-features--additions) |
| `cciptestinterfaces.Any2EVMMessageV1` (interface) / `EVMExtraArgsV1` (data) | added | `\bEVMExtraArgsV1\b` | `build/devenv/cciptestinterfaces/extra_args.go:75` | [New Features / Additions](#new-features--additions) |
| `cciptestinterfaces.EVMExtraArgsV2` (interface) / `EVMExtraArgsV2Data` | added | `\bEVMExtraArgsV2\b` | `build/devenv/cciptestinterfaces/extra_args.go:61` | [New Features / Additions](#new-features--additions) |
| `cciptestinterfaces.SVMExtraArgsV1` (interface) / `SVMExtraArgsV1Data` | added | `\bSVMExtraArgsV1\b` | `build/devenv/cciptestinterfaces/extra_args.go:88` | [New Features / Additions](#new-features--additions) |
| `evm.CCIP17EVM.BuildV3ExtraArgs` | added | — | `build/devenv/evm/impl.go:2191` | [New Features / Additions](#new-features--additions) |
| `evm.CCIP17EVM.GetExecutorArgs` | added | — | `build/devenv/evm/impl.go:2216` | [New Features / Additions](#new-features--additions) |
| `evm.CCIP17EVM.GetTokenArgs` | added | — | `build/devenv/evm/impl.go:2220` | [New Features / Additions](#new-features--additions) |
| `evm.SerializeMessageV3ExtraArgs` | added | — | `build/devenv/evm/impl.go:789` | [New Features / Additions](#new-features--additions) |
| `evm.BuildEVMExtraArgsV1` | added | — | `build/devenv/evm/impl.go:710` | [New Features / Additions](#new-features--additions) |
| `evm.BuildEVMExtraArgsV2` | added | — | `build/devenv/evm/impl.go:747` | [New Features / Additions](#new-features--additions) |
| `evm.BuildSVMExtraArgsV1` | added | — | `build/devenv/evm/impl.go:812` | [New Features / Additions](#new-features--additions) |
| `messaging.MessageV3TestScenario` | added | — | `build/devenv/tests/composable/messaging/agnostic_chain_test.go:15` | [New Features / Additions](#new-features--additions) |
| `messaging.EVMMessageV2TestScenario` | added | — | `build/devenv/tests/composable/messaging/agnostic_chain_test.go:66` | [New Features / Additions](#new-features--additions) |
| `messaging.SVMMessageV2TestScenario` | added | — | `build/devenv/tests/composable/messaging/agnostic_chain_test.go:107` | [New Features / Additions](#new-features--additions) |

## Breaking Changes

### `MessageOptions` loses `Version` and `UseTestRouter`

- **What changed:** struct moved from `interface.go` to a new `extra_args.go` and slimmed down.
- **Before:** `MessageOptions` carried `Version uint8` and `UseTestRouter bool` alongside the V3 fields.
- **After:** the struct holds only the V3 payload (`ExecutionGasLimit`, `OutOfOrderExecution`, `CCVs`, `FinalityConfig`, `Executor`, `ExecutorArgs`, `TokenArgs`) and now satisfies the new `ExtraArgsDataProvider` marker. There is a TODO at `build/devenv/cciptestinterfaces/extra_args.go:8` to rename it to `GenericExtraArgsV3` and to drop `OutOfOrderExecution` (kept for now for backward compatibility).
- **Why:** `Version` no longer belongs on the data struct — it is now passed alongside the provider so the registry can pick the right serializer. `UseTestRouter` is an EVM send-time concern and now lives on `evm.SendOptions` (which has been the case since `7b832388`).
- **Who is affected:** every caller building `MessageOptions{...}` literals with `Version: ...` or `UseTestRouter: ...` (every e2e test in `build/devenv/tests/e2e/`, `gun.go`, and `cli/send/command.go`).

### `Chain.SendMessage` signature

- **What changed:** generic `Chain` interface; method is now marked `// DEPRECATED: Use SendChainMessage instead.`
- **Before:**
  ```go
  SendMessage(ctx, dest uint64, fields MessageFields, opts MessageOptions) (MessageSentEvent, error)
  ```
- **After:**
  ```go
  SendMessage(ctx, dest uint64, fields MessageFields, dataProvider ExtraArgsDataProvider, messageVersion uint8) (MessageSentEvent, error)
  ```
- **Why:** `Version` was removed from the data struct, so the version is now an explicit parameter; the data parameter is the marker interface so SVM/V1/V2 providers are accepted.
- **Who is affected:** every `Chain` implementor and every caller. `*evm.CCIP17EVM.SendMessage` now type-asserts the provider to `MessageOptions` and invokes `SerializeEVMExtraArgs(messageVersion, opts)` internally — non-`MessageOptions` providers passed to the EVM impl error out. New code should call `BuildChainMessage` + `SendChainMessage` directly instead.

### `ChainAsSource.BuildChainMessage` takes serialized bytes

- **What changed:** `cciptestinterfaces.ChainAsSource.BuildChainMessage` signature.
- **Before:** `BuildChainMessage(ctx, destChain uint64, fields MessageFields, opts MessageOptions) (ChainAsSourceMessage, error)`
- **After:** `BuildChainMessage(ctx, fields MessageFields, extraArgs GenericExtraArgs) (GenericChainMessage, error)`
- **Why:** the source chain shouldn't know the destination's option struct or its selector — it only needs the opaque blob to embed in the on-chain message. Serialization moves up to the caller (a test scenario, CLI, or load gun), which knows which version + family it is targeting; the destination selector is supplied later at `SendChainMessage` time.
- **Who is affected:** every `ChainAsSource` implementor and every caller (`tests/e2e/gun.go:214`, `cli/send/command.go:144`, the new test scenarios in `tests/composable/messaging/agnostic_chain_test.go`). Callers must drop the `destChain uint64` argument and pass `GenericExtraArgs` (a `[]byte` alias).

### `ChainSendOption.IsSendOption()` return type

- **What changed:** marker method signature.
- **Before:** `IsSendOption() bool`
- **After:** `IsSendOption()`
- **Why:** the returned bool was never inspected.
- **Who is affected:** every `ChainSendOption` implementor. `evm.SendOptions.IsSendOption` already updated at `build/devenv/evm/interface.go:38`.

### `ExtraArgsSerializer` signature and registry key

- **What changed:** registered-serializer type and the `Register/GetExtraArgsSerializer` API.
- **Before:**
  ```go
  type ExtraArgsSerializer func(opts MessageOptions) []byte
  func RegisterExtraArgsSerializer(family string, serializer ExtraArgsSerializer)
  func GetExtraArgsSerializer(family string) (ExtraArgsSerializer, bool)
  ```
- **After:**
  ```go
  type ExtraArgsSerializer func(provider ExtraArgsDataProvider) (GenericExtraArgs, error)
  type ExtraArgsSerializerEntry struct { Version uint8; Family string }
  func RegisterExtraArgsSerializer(entry ExtraArgsSerializerEntry, serializer ExtraArgsSerializer)
  func GetExtraArgsSerializer(entry ExtraArgsSerializerEntry) (ExtraArgsSerializer, bool)
  ```
- **Why:** one serializer per (family, version) lets a single source chain encode different versions to the same destination family; the marker-interface input lets the same registry serve EVM and SVM providers; returning an error replaces the previous panic on unsupported types.
- **Who is affected:** any product repo that calls `RegisterExtraArgsSerializer`. EVM now registers seven entries in its `init()` (`build/devenv/evm/impl.go:120`): `(EVM, 1)`, `(EVM, 2)`, `(EVM, 3)`, `(Canton, 1)`, `(Canton, 2)`, `(Canton, 3)`, `(Solana, 1)`.

### `ChainAsSourceMessage` renamed to `GenericChainMessage`

- **What changed:** type alias in `cciptestinterfaces`.
- **Before:** `type ChainAsSourceMessage any`
- **After:** `type GenericChainMessage any`
- **Why:** the alias is also used as the input to `SendChainMessage`, so "as source" was misleading.
- **Who is affected:** any code that named the alias explicitly (tests typically rely on type inference).

## Migration Guide

1. **Strip `Version` and `UseTestRouter` from `MessageOptions` literals.** The struct keeps the V3 payload fields only.
   ```go
   // Before
   opts := cciptestinterfaces.MessageOptions{
       Version:             3,
       ExecutionGasLimit:   200_000,
       OutOfOrderExecution: false,
       UseTestRouter:       true,
   }
   // After
   opts := cciptestinterfaces.MessageOptions{
       ExecutionGasLimit:   200_000,
       OutOfOrderExecution: false,
   }
   // and pass UseTestRouter via evm.SendOptions on SendChainMessage:
   sendOpt := evm.SendOptions{UseTestRouter: true}
   ```

2. **Pass `messageVersion` explicitly to `Chain.SendMessage`** (or migrate to `BuildChainMessage` + `SendChainMessage`):
   ```go
   // Before
   evt, err := src.SendMessage(ctx, dest, fields, opts)
   // After (deprecated path, still works)
   evt, err := src.SendMessage(ctx, dest, fields, opts, 3) // version is now an explicit arg
   ```

3. **Serialize before calling `BuildChainMessage`, and drop the `destChain` argument:**
   ```go
   // Before
   msg, err := src.BuildChainMessage(ctx, destSel, fields, opts)

   // After — using the EVM family helper (CLI/load-gun pattern). The
   // destSel argument moves to SendChainMessage.
   extraArgs, err := evm.SerializeEVMExtraArgs(3, opts)
   if err != nil { /* handle */ }
   msg, err := src.BuildChainMessage(ctx, fields, extraArgs)
   sentEvent, _, err := src.SendChainMessage(ctx, destSel, msg, sendOption)
   ```

4. **`ChainSendOption` implementors:** drop the `bool` return.
   ```go
   // Before: func (o SendOptions) IsSendOption() bool { return true }
   // After:  func (o SendOptions) IsSendOption() {}
   ```

5. **Update `RegisterExtraArgsSerializer` calls in product repos:**
   ```go
   // Before
   cciptestinterfaces.RegisterExtraArgsSerializer(chainsel.FamilyEVM, SerializeEVMExtraArgs)
   // After — register one entry per supported version, with a serializer that
   // takes ExtraArgsDataProvider and returns (GenericExtraArgs, error)
   cciptestinterfaces.RegisterExtraArgsSerializer(
       cciptestinterfaces.ExtraArgsSerializerEntry{Family: chainsel.FamilyEVM, Version: 3},
       SerializeMessageV3ExtraArgs,
   )
   ```

6. **Rename type references:** `cciptestinterfaces.ChainAsSourceMessage` → `cciptestinterfaces.GenericChainMessage`.

7. **Migrate generic test scenarios.** `BasicMessageTestScenario` was deleted. Use the per-version helpers in `tests/composable/messaging/agnostic_chain_test.go` (note: the helpers no longer take a `*testing.T`):
   - `MessageV3TestScenario` — type-asserts the destination to `MessageV3Destination` (for `GetExecutorArgs` / `GetTokenArgs`) and the source to `MessageV3Source` (which exposes `BuildV3ExtraArgs`).
   - `EVMMessageV2TestScenario` — type-asserts the source to `EVMExtraArgsV2` and serializes via `BuildEVMExtraArgsV2`.
   - `SVMMessageV2TestScenario` — type-asserts the source to `SVMExtraArgsV1` and serializes via `BuildSVMExtraArgsV1`.

   `TestEVM2EVMPOC` is gone; use `TestEVM2EVMV3` and `TestEVM2EVMV2` in `evmPOC_test.go` as references.

## New Features / Additions

- **`cciptestinterfaces.ExtraArgsDataProvider`** — marker interface (`IsExtraArgsDataProvider()`) satisfied by every chain-shaped extra-args struct. See `build/devenv/cciptestinterfaces/interface.go:386`.
- **Generic byte-slice aliases** that document where serialized blobs flow. Plain `[]byte` is still accepted because of the alias relationship:
  - `GenericExtraArgs []byte` — output of every serializer / input to `BuildChainMessage` (`interface.go:432`).
  - `MessageV3ExecutorArgs []byte`, `MessageV3TokenArgs []byte` — return types of `MessageV3Destination.GetExecutorArgs` / `GetTokenArgs` (`extra_args.go:31`/`:34`).
- **Per-(version, family) data structs**, all in `build/devenv/cciptestinterfaces/extra_args.go`:
  - `MessageOptions` (V3, currently chain-agnostic; carries `FinalityConfig`, `CCVs`, etc.)
  - `EVMExtraArgsV1` (`GasLimit`)
  - `EVMExtraArgsV2Data` (`GasLimit`, `AllowOutOfOrderExecution`)
  - `SVMExtraArgsV1Data` (`Version`, `ComputeUnits`, `AccountIsWritableBitmap`, `AllowOutOfOrderExecution`, `TokenReceiver`, `Accounts`)
- **Optional source-side interfaces** that chain families can implement à la carte; generic test scenarios type-assert to them:
  - `MessageV3Source` — `BuildV3ExtraArgs(opts MessageOptions, destChain MessageV3Destination, executorArgsParams any, tokenArgsParams any) (GenericExtraArgs, error)`. The implementation is expected to call into `destChain.GetExecutorArgs` / `GetTokenArgs` and then serialize the resulting `MessageOptions`. EVM's implementation lives at `build/devenv/evm/impl.go:2191`.
  - `Any2EVMMessageV1` — `BuildEVMExtraArgsV1(opts any) (GenericExtraArgs, error)` (the interface kept its old name; only the method was renamed).
  - `EVMExtraArgsV2` — `BuildEVMExtraArgsV2(opts any) (GenericExtraArgs, error)`
  - `SVMExtraArgsV1` — `BuildSVMExtraArgsV1(opts any) (GenericExtraArgs, error)`
- **Optional destination-side interface `MessageV3Destination`** — `GetExecutorArgs(opts any) (MessageV3ExecutorArgs, error)` and `GetTokenArgs(opts any) (MessageV3TokenArgs, error)` for V3-specific destination-shape helpers. See `build/devenv/cciptestinterfaces/extra_args.go:38`.
- **EVM per-(version, family) builders**, each type-asserting the provider:
  - `SerializeMessageV3ExtraArgs`, `BuildEVMExtraArgsV1`, `BuildEVMExtraArgsV2`, `BuildSVMExtraArgsV1` (all in `build/devenv/evm/impl.go`). Each is exposed both as a free function (for the registry) and as a method on `*CCIP17EVM` (for satisfying the per-version source interfaces).
  - Thin EVM-specific dispatcher `SerializeEVMExtraArgs(version uint8, opts MessageOptions) ([]byte, error)` retained for callers (CLI, load gun, deprecated `Chain.SendMessage`) that hold a `MessageOptions` literal and a separate version. Note: this one still returns plain `[]byte` rather than `GenericExtraArgs`; the alias means callers can pass it straight into `BuildChainMessage`.
- **Generic test scenarios** in `build/devenv/tests/composable/messaging/agnostic_chain_test.go`: `MessageV3TestScenario`, `EVMMessageV2TestScenario`, `SVMMessageV2TestScenario`. They no longer take `*testing.T` — callers wrap with `require.NoError`. The `evmPOC_test.go` proof-of-concept was renamed and split into `TestEVM2EVMV3` and `TestEVM2EVMV2`.

## Examples

V3 send via the optional source/destination interfaces (matches `MessageV3TestScenario`):

```go
v3Source, _ := srcChain.(cciptestinterfaces.MessageV3Source)
v3Dest, _   := destChain.(cciptestinterfaces.MessageV3Destination)

extraArgs, err := v3Source.BuildV3ExtraArgs(
    cciptestinterfaces.MessageOptions{
        FinalityConfig:    opts.FinalityConfig,
        ExecutionGasLimit: opts.ExecutionGasLimit,
        Executor:          opts.Executor,
        CCVs:              opts.CCVs,
    },
    v3Dest,
    executorArgsParams,
    tokenArgsParams,
)

msg, err := srcChain.BuildChainMessage(ctx, fields, extraArgs)
sentEvent, _, err := srcChain.SendChainMessage(ctx, destChain.ChainSelector(), msg, sendOption)
```

V2 send (EVM destination):

```go
v2Source, _ := srcChain.(cciptestinterfaces.EVMExtraArgsV2)
extraArgs, err := v2Source.BuildEVMExtraArgsV2(cciptestinterfaces.EVMExtraArgsV2Data{
    GasLimit:                 200_000,
    AllowOutOfOrderExecution: false,
})
msg, err := srcChain.BuildChainMessage(ctx, fields, extraArgs)
sentEvent, _, err := srcChain.SendChainMessage(ctx, destChain.ChainSelector(), msg, sendOption)
```

CLI / load-gun pattern, using the EVM-specific dispatcher when the caller already has a `MessageOptions`:

```go
extraArgs, err := evm.SerializeEVMExtraArgs(3, messageOptions)
msg, err := senderImpl.BuildChainMessage(ctx, fields, extraArgs)
sentEvent, _, err := senderImpl.SendChainMessage(ctx, destSel, msg, evm.SendOptions{UseTestRouter: useTestRouter})
```

## References

- Branch: `aw/extraArgInterfaces`.
- Commits on `aw/extraArgInterfaces` vs `main`: `2ff7e6d2` (switch messageOptions to an interface), `d5ba454f` (bring extra args back to cciptestinterfaces, use optional interfaces for the extra args builder), `275a1f8b` (functional options pattern), `e2e1f8f6` (changelog), `7b832388` (remove testrouter from message options), `f96ba86f` (use distinct structs for different extra arg types), `27d65801` (update to buildv3 message instead of serializing), `5c94c317` (comments, spacing, lint), `76ab9fd5` (copilot changes, some comments), `390b0faf` (changelog rename), `ccc160ba` / `c1eb3da3` (lint, drop transient CI smoke entry), `d79bb2f4` (rename `Any2EVM*`/`Any2SVM*` types to `EVMExtraArgs*`/`SVMExtraArgs*`, introduce `GenericExtraArgs`), `215fce50` (drop `destChain` from `BuildChainMessage`, add `MessageV3ExecutorArgs`/`MessageV3TokenArgs`).
- Prior changelog entries this builds on: `2026-04-20_composable_chain_interfaces.md` (introduced `ChainAsSource` / `ChainAsDestination` / `ChainSendOption`).
