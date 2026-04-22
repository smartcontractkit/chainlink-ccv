# Human Overview

This document outlines changes that decouple extra-args serialization from the generic `cciptestinterfaces` layer and move it into a chain-family-scoped, type-dispatched model. The generic `MessageOptions` struct (which bundled EVM-shaped fields like `ExecutionGasLimit`, `OutOfOrderExecution`, and `UseTestRouter` with chain-agnostic fields like `CCVs`/`Executor`) is removed from `cciptestinterfaces` and replaced with:

1. A new marker interface `cciptestinterfaces.ExtraArgsDataProvider` that any chain family's options struct implements.
2. Family-specific options types in each chain package (`evm.MessageOptions`, `evm.SVMMessageOptions`, etc.) that satisfy the marker.
3. A new `ExtraArgsSerializer` method on `ChainAsSource` that a source chain uses to turn a provider into serialized extra-args bytes via a runtime type switch.

This continues the direction started in `2026-04-20_composable_chain_interfaces.md` — shrinking the generic `Chain` / `ChainAsSource` / `ChainAsDestination` surface and pushing family-specific knowledge into each family's package.

## Summary of Changes

### New marker interface in `cciptestinterfaces`

```go
// ExtraArgsDataProvider is a marker interface for destination-shaped extra-args data.
// A source chain's BuildChainMessage type-switches on the concrete provider to pick
// the right encoder. Each chain family defines its own concrete provider struct.
type ExtraArgsDataProvider interface {
    IsExtraArgsDataProvider()
}
```

Unlike `ChainSendOption` (which uses a `bool`-returning marker method), `ExtraArgsDataProvider` uses a no-return marker — the method exists purely for compile-time type constraint.

### `MessageOptions` moved out of `cciptestinterfaces`

The `MessageOptions` struct previously defined in `cciptestinterfaces/interface.go` has been removed entirely from that package and relocated to `build/devenv/evm/types.go` as EVM-specific:

```go
// build/devenv/evm/types.go
type MessageOptions struct {
    Version             uint8
    ExecutionGasLimit   uint32
    OutOfOrderExecution bool
    CCVs                []protocol.CCV
    FinalityConfig      protocol.Finality
    Executor            protocol.UnknownAddress
    ExecutorArgs        []byte
    TokenArgs           []byte
    UseTestRouter       bool
}

func (m MessageOptions) IsExtraArgsDataProvider() {}
```

The same file introduces a first-cut Solana options struct (marked with a `TODO` to eventually be imported from the Solana family package):

```go
type SVMMessageOptions struct {
    Version                  uint8
    ComputeUnits             uint32
    AccountIsWritableBitmap  uint64
    AllowOutOfOrderExecution bool
    TokenReceiver            [32]byte
    Accounts                 [][32]byte
}

func (m SVMMessageOptions) IsExtraArgsDataProvider() {}
```

Previously the SVM V1 serializer re-used fields from the generic EVM-shaped `MessageOptions` (`ExecutionGasLimit` was used as `ComputeUnits`, `TokenReceiver` and `Accounts` were hard-coded to zero values). The new `SVMMessageOptions` exposes those fields natively.

### `Chain.SendMessage` signature change

```go
// before
SendMessage(ctx context.Context, dest uint64, fields MessageFields, opts MessageOptions) (MessageSentEvent, error)

// after
SendMessage(ctx context.Context, dest uint64, fields MessageFields, dataProvider ExtraArgsDataProvider) (MessageSentEvent, error)
```

Callers now pass `evm.MessageOptions{...}` (or a future `svm.MessageOptions{...}`) where they previously passed `cciptestinterfaces.MessageOptions{...}`. The EVM implementation type-asserts the provider and returns an error if the type is wrong.

### `ChainAsSource` interface changes

```go
type ChainAsSource interface {
    genericChain
    // NEW
    ExtraArgsSerializer(ExtraArgsDataProvider) ([]byte, error)
    // CHANGED: opts MessageOptions → extraArgs []byte
    BuildChainMessage(ctx context.Context, destChain uint64, messageFields MessageFields, extraArgs []byte) (GenericChainMessage, error)
    // renamed type alias only
    SendChainMessage(ctx context.Context, destChain uint64, message GenericChainMessage, sendOption ChainSendOption) (MessageSentEvent, protocol.ByteSlice, error)
    ConfirmSendOnSource(ctx context.Context, to uint64, key MessageEventKey, timeout time.Duration) (MessageSentEvent, error)
}
```

`BuildChainMessage` no longer serializes extra args internally — callers must serialize first via `ExtraArgsSerializer` and pass raw bytes. This splits concerns: provider-shape dispatch happens in one place, message assembly in another.

`ChainAsDestination` gains a commented-out method signature (not yet implemented) hinting at the planned next step of having destinations produce their own provider:

```go
// ExtraArgsProvider returns the extra-args data provider for this destination chain.
// The output of this method will be passed to the ExtraArgsEncoder in ChainAsSource.
// ExtraArgsProvider(any) (ExtraArgsDataProvider, error)
```

### Renamed: `ChainAsSourceMessage` → `GenericChainMessage`

The opaque type alias used to pass a built message from `BuildChainMessage` into `SendChainMessage` is renamed. Behaviourally identical (`type GenericChainMessage any`).

### `ExtraArgsSerializer` function type change

```go
// before
type ExtraArgsSerializer func(opts MessageOptions) []byte

// after
type ExtraArgsSerializer func(provider ExtraArgsDataProvider) ([]byte, error)
```

Along with the signature change, the dispatch mechanism inside EVM is rewritten:

- **Before:** `serializeExtraArgs(opts, destFamily)` looked up a serializer in the package-global `extraArgsSerializers` map keyed by destination-chain-family string (`"EVM"`, `"SVM"`, …), then panicked if nothing was registered.
- **After:** `CCIP17EVM.ExtraArgsSerializer` type-switches on the concrete provider:

```go
func (m *CCIP17EVM) ExtraArgsSerializer(provider cciptestinterfaces.ExtraArgsDataProvider) ([]byte, error) {
    switch p := provider.(type) {
    case MessageOptions:
        return SerializeEVMExtraArgs(p)
    case SVMMessageOptions:
        return SerializeSVMExtraArgs(p)
    default:
        return nil, fmt.Errorf("unsupported ExtraArgsDataProvider type %T", provider)
    }
}
```

`SerializeEVMExtraArgs` and `SerializeSVMExtraArgs` now take `ExtraArgsDataProvider`, re-assert to their concrete type, and return `([]byte, error)` instead of `[]byte` (errors replace a caller-side panic for type-mismatch; version-mismatch still panics inside the switch).

### EVM `SendMessage` implementation

`SendMessage` no longer just delegates to `BuildChainMessage` + `SendChainMessage`. Because `BuildChainMessage` now takes pre-serialized bytes, `SendMessage` does the serialization + message construction inline:

```go
func (m *CCIP17EVM) SendMessage(ctx context.Context, dest uint64, fields cciptestinterfaces.MessageFields, extraArgsProvider cciptestinterfaces.ExtraArgsDataProvider) (cciptestinterfaces.MessageSentEvent, error) {
    opts, ok := extraArgsProvider.(MessageOptions)
    if !ok {
        return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("extraArgsProvider is not a MessageOptions")
    }
    extraArgs, err := m.ExtraArgsSerializer(opts)
    if err != nil {
        return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to serialize extra args: %w", err)
    }

    msg := routerwrapper.ClientEVM2AnyMessage{
        Receiver:  common.LeftPadBytes(fields.Receiver.Bytes(), 32),
        Data:      fields.Data,
        FeeToken:  common.HexToAddress(fields.FeeToken.String()),
        ExtraArgs: extraArgs,
    }
    // ... token amount, then delegate to SendChainMessage
}
```

### Composable scenario helper (`tests/composable/messaging/messageAsSource.go`)

`BasicMessageTestScenario` now takes an `ExtraArgsDataProvider` and performs the two-step serialize-then-build dance:

```go
func BasicMessageTestScenario(
    ctx context.Context,
    t *testing.T,
    srcChain cciptestinterfaces.ChainAsSource,
    destChain cciptestinterfaces.ChainAsDestination,
    fields cciptestinterfaces.MessageFields,
    extraArgsProvider cciptestinterfaces.ExtraArgsDataProvider,
    sendOption cciptestinterfaces.ChainSendOption,
) error {
    extraArgs, err := srcChain.ExtraArgsSerializer(extraArgsProvider)
    if err != nil {
        return fmt.Errorf("failed to serialize extra args: %w", err)
    }
    // TODO: destination chains will eventually produce their own provider via
    // ChainAsDestination. For now callers construct the provider literally and pass it in.
    srcMessage, err := srcChain.BuildChainMessage(ctx, destChain.ChainSelector(), fields, extraArgs)
    // ...
}
```

### Load-test gun (`tests/e2e/gun.go`)

The gun was updated analogously — it now calls `chainAsSource.ExtraArgsSerializer(opts)` before `BuildChainMessage`. `selectMessageProfile` returns `evm.MessageOptions` instead of `cciptestinterfaces.MessageOptions`.

### `smoke_chain_statuses_cli_test.go` tightening

Independent of the provider refactor, this test was simplified: `SendMessage` already returns a `MessageSentEvent` carrying the `MessageID`, so the prior `GetExpectedNextSequenceNumber` + `SendMessage` + `ConfirmSendOnSource(..., SeqNum: seqNo)` pattern is collapsed to `SendMessage` (capturing the event) + `ConfirmSendOnSource(..., MessageID: sentEvent.MessageID)`.

### Call-site updates

Every call site that previously constructed `cciptestinterfaces.MessageOptions{...}` now constructs `evm.MessageOptions{...}`. Files touched:

- `cli/send/command.go`
- `tests/composable/messaging/evmPOC_test.go`
- `tests/e2e/finality_reorg_curse_test.go`
- `tests/e2e/gun.go`
- `tests/e2e/ha_test.go`
- `tests/e2e/smoke_chain_statuses_cli_test.go`
- `tests/e2e/smoke_extra_args_v2_test.go`
- `tests/e2e/smoke_replay_cli_test.go`
- `tests/e2e/smoke_token_verification_test.go`
- `tests/e2e/tcapi/basic/v3.go`
- `tests/e2e/tcapi/token_transfer/v3.go`

## Marker interface pattern (recap)

`ExtraArgsDataProvider` is the third marker interface in this test framework, joining `ChainSendOption` and `EVMOptions`. They serve distinct roles:

| Marker | Carried through | Dispatched by | Purpose |
|---|---|---|---|
| `ChainSendOption` | `SendChainMessage` | Source chain asserts to its own family's struct | Per-send knobs (nonce, sender, flags) scoped to the **source** family |
| `ExtraArgsDataProvider` | `ExtraArgsSerializer` / `BuildChainMessage` | Source chain type-switches over **destination** family's provider type | Chain-family-shaped extra-args input, serialized into bytes at the source |
| `EVMOptions` | Not passed; recovered via type assertion on `Chain` | Caller asserts when it needs EVM capabilities | Capabilities that only exist on EVM (`GetUserNonce`, `GetRoundRobinUser`) |

The pattern in all three cases is: keep the shared interface free of type parameters, pay for it with a single runtime type assertion inside the family-specific implementation.

## Adoption guide

### Updating a call site

```go
// before
_, err := chain.SendMessage(ctx, dest, cciptestinterfaces.MessageFields{...}, cciptestinterfaces.MessageOptions{
    Version:             2,
    ExecutionGasLimit:   200_000,
    OutOfOrderExecution: true,
})

// after
_, err := chain.SendMessage(ctx, dest, cciptestinterfaces.MessageFields{...}, evm.MessageOptions{
    Version:             2,
    ExecutionGasLimit:   200_000,
    OutOfOrderExecution: true,
})
```

### Using `ChainAsSource` directly

If you were already calling `BuildChainMessage` + `SendChainMessage`, you now need to serialize extra args first:

```go
extraArgs, err := srcChain.ExtraArgsSerializer(evm.MessageOptions{Version: 3, /* ... */})
require.NoError(t, err)

msg, err := srcChain.BuildChainMessage(ctx, destSelector, fields, extraArgs)
require.NoError(t, err)

sentEvent, txHash, err := srcChain.SendChainMessage(ctx, destSelector, msg, evm.EVMSendOptions{/* ... */})
```

### Adding a new destination family's provider

1. Define the provider struct in the destination family's package with whatever fields its extra-args encoding needs.
2. Satisfy the marker: `func (o MyFamilyMessageOptions) IsExtraArgsDataProvider() {}`.
3. Teach each source family's `ExtraArgsSerializer` to recognise it — currently a case added to `CCIP17EVM.ExtraArgsSerializer`'s type switch. (A future change may move this to `ChainAsDestination.ExtraArgsProvider`, see the commented-out signature in `cciptestinterfaces.ChainAsDestination`.)

## Deprecated / Renamed APIs

| Symbol | Removed from | Replacement |
|---|---|---|
| `cciptestinterfaces.MessageOptions` | `cciptestinterfaces` | `evm.MessageOptions` (EVM family) / `evm.SVMMessageOptions` (Solana family, provisional) |
| `ExtraArgsSerializer func(MessageOptions) []byte` | `cciptestinterfaces` | `ExtraArgsSerializer func(ExtraArgsDataProvider) ([]byte, error)` |
| `ChainAsSourceMessage` | `cciptestinterfaces` (renamed, not removed) | `GenericChainMessage` |
| `ChainAsSource.BuildChainMessage(..., opts MessageOptions)` | `cciptestinterfaces.ChainAsSource` | `BuildChainMessage(..., extraArgs []byte)` + `ChainAsSource.ExtraArgsSerializer(ExtraArgsDataProvider)` |
| `Chain.SendMessage(..., opts MessageOptions)` | `cciptestinterfaces.Chain` | `SendMessage(..., dataProvider ExtraArgsDataProvider)` |
| internal `serializeExtraArgs(opts, destFamily string)` | `build/devenv/evm/impl.go` | `CCIP17EVM.ExtraArgsSerializer` (type-switch on provider) |

The package-global `extraArgsSerializers` registry and `RegisterExtraArgsSerializer` remain in `cciptestinterfaces` but are no longer called by EVM — dispatch now happens inside each chain's `ExtraArgsSerializer` method.
