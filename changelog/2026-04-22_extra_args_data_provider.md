# Per-version `ExtraArgsDataProvider` structs and pre-serialized extra args on `BuildChainMessage`

## Executive Summary

- Replaces the single EVM-shaped `cciptestinterfaces.MessageOptions` (with a `Version` field) with one `ExtraArgsDataProvider`-implementing struct per `(message version, destination family)` and switches the registry / source-chain plumbing to look up serializers by `(family, version)`.
- Motivated by adding non-EVM destinations (Solana) and non-V3 message versions: a single struct could not represent V1/V2/V3-EVM and V1-SVM extra args without overloading fields.
- Affects every implementor of `cciptestinterfaces.Chain`, `ChainAsSource`, `ChainSendOption`, and `ExtraArgsSerializer`, plus every test or CLI that built a `MessageOptions` literal — `MessageOptions.Version` and `MessageOptions.UseTestRouter` no longer exist.
- Breaking: `Chain.SendMessage` takes an `ExtraArgsDataProvider` plus a separate `messageVersion uint8`; `ChainAsSource.BuildChainMessage` takes pre-serialized `[]byte`; `ChainSendOption.IsSendOption()` loses its `bool` return; `ExtraArgsSerializer` returns `(..., error)` and is keyed by `ExtraArgsSerializerEntry{Family, Version}`; `ChainAsSourceMessage` renamed to `GenericChainMessage`.

## AI Adapter Index

Read this table first. For each row, run the `Search` pattern against the consumer repo; if it produces hits, follow the linked `Section` for migration detail. Symbols not in this table are unchanged — do not load source for them. The `evm.*` and `messaging.*` rows live in this repo's `build/devenv/...` tree; downstream repos that vendor or shadow these packages should look in the corresponding paths.

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `cciptestinterfaces.Chain.SendMessage` | signature-changed (and deprecated) | `\.SendMessage\(` | `build/devenv/cciptestinterfaces/interface.go:144` | [Chain.SendMessage signature](#chainsendmessage-signature) |
| `cciptestinterfaces.ChainAsSource.BuildChainMessage` | signature-changed | `\.BuildChainMessage\(` | `build/devenv/cciptestinterfaces/interface.go:414` | [ChainAsSource.BuildChainMessage takes serialized bytes](#chainassourcebuildchainmessage-takes-serialized-bytes) |
| `cciptestinterfaces.ChainSendOption.IsSendOption` | signature-changed | `\bIsSendOption\(\)` | `build/devenv/cciptestinterfaces/interface.go:380` | [ChainSendOption.IsSendOption() return type](#chainsendoptionissendoption-return-type) |
| `cciptestinterfaces.ExtraArgsSerializer` | signature-changed | `\bExtraArgsSerializer\b` | `build/devenv/cciptestinterfaces/interface.go:319` | [ExtraArgsSerializer signature and registry key](#extraargsserializer-signature-and-registry-key) |
| `cciptestinterfaces.RegisterExtraArgsSerializer` | signature-changed | `\bRegisterExtraArgsSerializer\(` | `build/devenv/cciptestinterfaces/interface.go:335` | [ExtraArgsSerializer signature and registry key](#extraargsserializer-signature-and-registry-key) |
| `cciptestinterfaces.GetExtraArgsSerializer` | signature-changed | `\bGetExtraArgsSerializer\(` | `build/devenv/cciptestinterfaces/interface.go:345` | [ExtraArgsSerializer signature and registry key](#extraargsserializer-signature-and-registry-key) |
| `cciptestinterfaces.MessageOptions.Version` | removed | `\bVersion:\s*\d` | — | [MessageOptions loses Version and UseTestRouter](#messageoptions-loses-version-and-usetestrouter) |
| `cciptestinterfaces.MessageOptions.UseTestRouter` | removed | `\bUseTestRouter\b` | — | [MessageOptions loses Version and UseTestRouter](#messageoptions-loses-version-and-usetestrouter) |
| `evm.SerializeEVMExtraArgs` | signature-changed | `\bSerializeEVMExtraArgs\(` | `build/devenv/evm/impl.go:692` | [ExtraArgsSerializer signature and registry key](#extraargsserializer-signature-and-registry-key) |
| `evm.SerializeSVMExtraArgs` | removed | `\bSerializeSVMExtraArgs\b` | — | [ExtraArgsSerializer signature and registry key](#extraargsserializer-signature-and-registry-key) |
| `messaging.BasicMessageTestScenario` | removed | `\bBasicMessageTestScenario\b` | — | [Migration Guide step 7](#migration-guide) |
| `cciptestinterfaces.ChainAsSourceMessage → cciptestinterfaces.GenericChainMessage` | renamed | `\bChainAsSourceMessage\b` | `build/devenv/cciptestinterfaces/interface.go:428` | [ChainAsSourceMessage renamed to GenericChainMessage](#chainassourcemessage-renamed-to-genericchainmessage) |
| `messaging.TestEVM2EVMPOC → messaging.TestEVM2EVMV3` | renamed | `\bTestEVM2EVMPOC\b` | `build/devenv/tests/composable/messaging/evmPOC_test.go:26` | [Migration Guide step 7](#migration-guide) |
| `cciptestinterfaces.ExtraArgsDataProvider` | added | — | `build/devenv/cciptestinterfaces/interface.go:386` | [New Features / Additions](#new-features--additions) |
| `cciptestinterfaces.ExtraArgsOption` | added | — | `build/devenv/cciptestinterfaces/extra_args.go:12` | [New Features / Additions](#new-features--additions) |
| `cciptestinterfaces.ExtraArgsSerializerEntry` | added | — | `build/devenv/cciptestinterfaces/interface.go:326` | [ExtraArgsSerializer signature and registry key](#extraargsserializer-signature-and-registry-key) |
| `cciptestinterfaces.MessageV3Source` | added | — | `build/devenv/cciptestinterfaces/extra_args.go:49` | [New Features / Additions](#new-features--additions) |
| `cciptestinterfaces.MessageV3Destination` | added | — | `build/devenv/cciptestinterfaces/extra_args.go:38` | [New Features / Additions](#new-features--additions) |
| `cciptestinterfaces.Any2EVMMessageV1` / `Any2EVMMessageV1Data` | added | — | `build/devenv/cciptestinterfaces/extra_args.go:68` | [New Features / Additions](#new-features--additions) |
| `cciptestinterfaces.Any2EVMMessageV2` / `Any2EVMMessageV2Data` | added | — | `build/devenv/cciptestinterfaces/extra_args.go:54` | [New Features / Additions](#new-features--additions) |
| `cciptestinterfaces.Any2SVMMessageV1` / `Any2SVMMessageV1Data` | added | — | `build/devenv/cciptestinterfaces/extra_args.go:81` | [New Features / Additions](#new-features--additions) |
| `evm.CCIP17EVM.ExtraArgsBuilder` | added | — | `build/devenv/evm/impl.go:2032` | [New Features / Additions](#new-features--additions) |
| `evm.SerializeMessageV3ExtraArgs` | added | — | `build/devenv/evm/impl.go:774` | [New Features / Additions](#new-features--additions) |
| `evm.SerializeAny2EVMMessageV1` | added | — | `build/devenv/evm/impl.go:705` | [New Features / Additions](#new-features--additions) |
| `evm.SerializeAny2EVMMessageV2` | added | — | `build/devenv/evm/impl.go:737` | [New Features / Additions](#new-features--additions) |
| `evm.SerializeAny2SVMMessageV1` | added | — | `build/devenv/evm/impl.go:793` | [New Features / Additions](#new-features--additions) |
| `messaging.MessageV3TestScenario` | added | — | `build/devenv/tests/composable/messaging/agnostic_chain_test.go:16` | [New Features / Additions](#new-features--additions) |
| `messaging.MessageV2TestScenario` | added | — | `build/devenv/tests/composable/messaging/agnostic_chain_test.go:91` | [New Features / Additions](#new-features--additions) |

## Breaking Changes

### `MessageOptions` loses `Version` and `UseTestRouter`

- **What changed:** struct moved from `interface.go` to a new `extra_args.go` and slimmed down.
- **Before:** `MessageOptions` carried `Version uint8` and `UseTestRouter bool` alongside the V3 fields.
- **After:** the struct holds only the V3 payload (ExecutionGasLimit, OutOfOrderExecution, CCVs, FinalityConfig, Executor, ExecutorArgs, TokenArgs) and now satisfies the new `ExtraArgsDataProvider` marker. There is a TODO at `build/devenv/cciptestinterfaces/extra_args.go:15` to rename it to `Any2AnyMessageV3Data`.
- **Why:** `Version` no longer belongs on the data struct — it is now passed alongside the provider so the registry can pick the right serializer. `UseTestRouter` is an EVM send-time concern and now lives on `evm.SendOptions`.
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
- **Who is affected:** every `Chain` implementor and every caller. `*evm.CCIP17EVM.SendMessage` now type-asserts the provider to `MessageOptions` and invokes `SerializeEVMExtraArgs(messageVersion, opts)` internally — non-EVM providers passed to the EVM impl error out.

### `ChainAsSource.BuildChainMessage` takes serialized bytes

- **What changed:** `cciptestinterfaces.ChainAsSource.BuildChainMessage` signature.
- **Before:** `BuildChainMessage(ctx, destChain, fields, opts MessageOptions) (ChainAsSourceMessage, error)`
- **After:** `BuildChainMessage(ctx, destChain, fields, extraArgs []byte) (GenericChainMessage, error)`
- **Why:** the source chain shouldn't know the destination's option struct; it only needs the opaque blob to embed in the on-chain message. Serialization moves up to the caller (a test scenario, CLI, or load gun), which knows which version + family it is targeting.
- **Who is affected:** every `ChainAsSource` implementor and every caller (`tests/e2e/gun.go:209`, `cli/send/command.go:144`, the new test scenarios in `tests/composable/messaging/agnostic_chain_test.go`).

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
  type ExtraArgsSerializer func(provider ExtraArgsDataProvider) ([]byte, error)
  type ExtraArgsSerializerEntry struct { Version uint8; Family string }
  func RegisterExtraArgsSerializer(entry ExtraArgsSerializerEntry, serializer ExtraArgsSerializer)
  func GetExtraArgsSerializer(entry ExtraArgsSerializerEntry) (ExtraArgsSerializer, bool)
  ```
- **Why:** one serializer per (family, version) lets a single source chain encode different versions to the same destination family; the marker-interface input lets the same registry serve EVM and SVM providers; returning an error replaces the previous panic on unsupported types.
- **Who is affected:** any product repo that calls `RegisterExtraArgsSerializer`. EVM now registers four entries (`build/devenv/evm/impl.go:120`): `(EVM, 1)`, `(EVM, 2)`, `(EVM, 3)`, `(Canton, 1)`, `(Canton, 2)`, `(Canton, 3)`, `(Solana, 1)`.

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

2. **Pass `messageVersion` explicitly to `Chain.SendMessage`:**
   ```go
   // Before
   evt, err := src.SendMessage(ctx, dest, fields, opts)
   // After
   evt, err := src.SendMessage(ctx, dest, fields, opts, 3) // version is now an explicit arg
   ```

3. **Serialize before calling `BuildChainMessage`:**
   ```go
   // Before
   msg, err := src.BuildChainMessage(ctx, destSel, fields, opts)

   // After — using the EVM family helper (CLI/load-gun pattern)
   extraArgs, err := evm.SerializeEVMExtraArgs(3, opts)
   if err != nil { /* handle */ }
   msg, err := src.BuildChainMessage(ctx, destSel, fields, extraArgs)
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
   // takes ExtraArgsDataProvider and returns ([]byte, error)
   cciptestinterfaces.RegisterExtraArgsSerializer(
       cciptestinterfaces.ExtraArgsSerializerEntry{Family: chainsel.FamilyEVM, Version: 3},
       SerializeMessageV3ExtraArgs,
   )
   ```

6. **Rename type references:** `cciptestinterfaces.ChainAsSourceMessage` → `cciptestinterfaces.GenericChainMessage`.

7. **Migrate generic test scenarios.** `BasicMessageTestScenario` was deleted. Use the per-version helpers in `tests/composable/messaging/agnostic_chain_test.go`:
   - `MessageV3TestScenario` — type-asserts the destination to `MessageV3Destination` (for `GetExecutorArgs` / `GetTokenArgs`) and the source to `MessageV3Source` (for `SerializeMessageV3ExtraArgs`).
   - `MessageV2TestScenario` — type-asserts the source to `Any2EVMMessageV2` and serializes via `SerializeAny2EVMMessageV2`.

## New Features / Additions

- **`cciptestinterfaces.ExtraArgsDataProvider`** — marker interface satisfied by every chain-shaped extra-args struct. See `build/devenv/cciptestinterfaces/interface.go:386`.
- **Per-(version, family) data structs**, all in `build/devenv/cciptestinterfaces/extra_args.go`:
  - `MessageOptions` (V3, currently chain-agnostic; carries `FinalityConfig`, `CCVs`, etc.)
  - `Any2EVMMessageV1Data` (`GasLimit`)
  - `Any2EVMMessageV2Data` (`GasLimit`, `AllowOutOfOrderExecution`)
  - `Any2SVMMessageV1Data` (`Version`, `ComputeUnits`, `AccountIsWritableBitmap`, `AllowOutOfOrderExecution`, `TokenReceiver`, `Accounts`)
- **Optional source-side interfaces** that chain families can implement à la carte; generic test scenarios type-assert to them:
  - `MessageV3Source` — `SerializeMessageV3ExtraArgs(MessageOptions) ([]byte, error)`
  - `Any2EVMMessageV1` — `SerializeAny2EVMMessageV1(any) ([]byte, error)`
  - `Any2EVMMessageV2` — `SerializeAny2EVMMessageV2(any) ([]byte, error)`
  - `Any2SVMMessageV1` — `SerializeAny2SVMMessageV1(any) ([]byte, error)`
- **Optional destination-side interface** `MessageV3Destination` for V3-specific destination-shape helpers (`GetExecutorArgs`, `GetTokenArgs`). See `build/devenv/cciptestinterfaces/extra_args.go:38`.
- **`cciptestinterfaces.ExtraArgsOption`** — `func(ExtraArgsDataProvider) error`. Functional-option type intended for a future builder API; declared at `build/devenv/cciptestinterfaces/extra_args.go:12` and accepted by `*evm.CCIP17EVM.ExtraArgsBuilder` (`build/devenv/evm/impl.go:2032`). No `WithXxx` constructors are defined yet, and `ExtraArgsBuilder` is not yet wired into the standard test scenarios.
- **EVM per-(version, family) serializers**, each type-asserting the provider:
  - `SerializeMessageV3ExtraArgs`, `SerializeAny2EVMMessageV1`, `SerializeAny2EVMMessageV2`, `SerializeAny2SVMMessageV1` (all in `build/devenv/evm/impl.go`).
  - Thin EVM-specific dispatcher `SerializeEVMExtraArgs(version uint8, opts MessageOptions) ([]byte, error)` retained for callers (CLI, load gun) that hold a `MessageOptions` literal directly.
- **Generic test scenarios** in `build/devenv/tests/composable/messaging/agnostic_chain_test.go`: `MessageV3TestScenario`, `MessageV2TestScenario`. The `evmPOC_test.go` proof-of-concept was renamed and split into `TestEVM2EVMV3` and `TestEVM2EVMV2`.

## Examples

V3 send via the optional source/destination interfaces (matches `MessageV3TestScenario`):

```go
v3Source, _ := srcChain.(cciptestinterfaces.MessageV3Source)
v3Dest, _   := destChain.(cciptestinterfaces.MessageV3Destination)

execArgs, err := v3Dest.GetExecutorArgs(executorArgsParams)
tokenArgs, err := v3Dest.GetTokenArgs(tokenArgsParams)

extraArgs, err := v3Source.SerializeMessageV3ExtraArgs(cciptestinterfaces.MessageOptions{
    FinalityConfig:    opts.FinalityConfig,
    ExecutionGasLimit: opts.ExecutionGasLimit,
    Executor:          opts.Executor,
    ExecutorArgs:      execArgs,
    TokenArgs:         tokenArgs,
    CCVs:              opts.CCVs,
})

msg, err := srcChain.BuildChainMessage(ctx, destChain.ChainSelector(), fields, extraArgs)
sentEvent, _, err := srcChain.SendChainMessage(ctx, destChain.ChainSelector(), msg, sendOption)
```

V2 send (EVM destination):

```go
v2Source, _ := srcChain.(cciptestinterfaces.Any2EVMMessageV2)
extraArgs, err := v2Source.SerializeAny2EVMMessageV2(cciptestinterfaces.Any2EVMMessageV2Data{
    GasLimit:                 200_000,
    AllowOutOfOrderExecution: false,
})
msg, err := srcChain.BuildChainMessage(ctx, destChain.ChainSelector(), fields, extraArgs)
sentEvent, _, err := srcChain.SendChainMessage(ctx, destChain.ChainSelector(), msg, sendOption)
```

CLI / load-gun pattern, using the EVM-specific dispatcher when the caller already has a `MessageOptions`:

```go
extraArgs, err := evm.SerializeEVMExtraArgs(3, messageOptions)
msg, err := senderImpl.BuildChainMessage(ctx, destSel, fields, extraArgs)
sentEvent, _, err := senderImpl.SendChainMessage(ctx, destSel, msg, evm.SendOptions{UseTestRouter: useTestRouter})
```

## References

- Commits on `aw/extraArgsRemake` vs `main`: `2ff7e6d2` (switch messageOptions to an interface), `d5ba454f` (bring extra args back to cciptestinterfaces, use optional interfaces for the extra args builder), `275a1f8b` (functional options pattern), `e2e1f8f6` (changelog), `7b832388` (remove testrouter from message options), `1b31a48d` (use distinct structs for different extra arg types).
- Prior changelog entries this builds on: `2026-04-20_composable_chain_interfaces.md` (introduced `ChainAsSource` / `ChainAsDestination` / `ChainSendOption`).
