# Human Overview

This document outlines changes on the `aw/testAPIPOC` branch, which introduces composable chain interfaces to the devenv test framework. The primary goal is to decouple chain-family-specific send logic from the top-level `Chain` interface and replace it with a pair of narrower, composable interfaces — `ChainAsSource` and `ChainAsDestination` — enabling future non-EVM chain implementations without modifying shared test code.

## Summary of Changes

### New interfaces in `cciptestinterfaces`

Three new interfaces replace the EVM-specific methods previously on `Chain`:

```go
// ChainSendOption is a marker interface for chain-specific send parameters.
type ChainSendOption interface {
    IsSendOption() bool
}

// ChainAsSource is implemented by any chain that can originate CCIP messages.
type ChainAsSource interface {
    BuildChainMessage(ctx context.Context, destChain uint64, fields MessageFields, opts MessageOptions) (any, error)
    SendChainMessage(ctx context.Context, destChain uint64, message any, sendOption ChainSendOption) (MessageSentEvent, protocol.ByteSlice, error)
    ConfirmSendOnSource(ctx context.Context, to uint64, key MessageEventKey, timeout time.Duration) (MessageSentEvent, error)
    ChainSelector() uint64
}

// ChainAsDestination is implemented by any chain that can receive CCIP messages.
type ChainAsDestination interface {
    GetEOAReceiverAddress() (protocol.UnknownAddress, error)
    ConfirmExecOnDest(ctx context.Context, from uint64, key MessageEventKey, timeout time.Duration) (ExecutionStateChangedEvent, error)
    ChainSelector() uint64
}
```

The removed methods (`SendMessageWithNonce`, `GetUserNonce`, `GetRoundRobinUser`) were EVM-specific and have been moved to the new `evm.EVMOptions` interface.

### New EVM-specific types in `build/devenv/evm/interface.go`

```go
// EVMOptions exposes EVM-specific capabilities not part of the generic Chain interface.
type EVMOptions interface {
    GetRoundRobinUser() func() *bind.TransactOpts
    GetUserNonce(ctx context.Context, userAddress protocol.UnknownAddress) (uint64, error)
}

// EVMSendOptions is the ChainSendOption implementation for EVM chains.
type EVMSendOptions struct {
    Nonce                        *uint64
    Sender                       *bind.TransactOpts
    UseTestRouter                bool
    DisableTokenAmountValidation bool
}
```

`EVMSendOptions` consolidates the parameters that were previously spread across `SendMessageWithNonce`'s argument list.

### EVM implementation (`build/devenv/evm/impl.go`)

`CCIP17EVM` now implements `ChainAsSource` via two new methods:

- **`BuildChainMessage`** — constructs a `routerwrapper.ClientEVM2AnyMessage` from `MessageFields` and `MessageOptions` without sending it.
- **`SendChainMessage`** — accepts the pre-built message and an `EVMSendOptions`, looks up the router, validates token balances (unless `DisableTokenAmountValidation` is set), submits the transaction, and returns the `MessageSentEvent` along with the raw transaction hash bytes.

`SendMessage` now delegates to `BuildChainMessage` + `SendChainMessage`, preserving backward compatibility for existing callers.

The `eventKey` struct now includes `messageID` in addition to `chainSelector` and `msgNum`, improving event lookup reliability.

### Composable test helpers (`build/devenv/tests/composable/`)

A new package `messaging` contains reusable scenario helpers built entirely on the new interfaces:

```go
// BasicMessageTestScenario sends a message from srcChain to destChain and
// asserts successful execution, using only the ChainAsSource / ChainAsDestination
// interfaces — no EVM-specific types.
func BasicMessageTestScenario(
    ctx context.Context,
    t *testing.T,
    srcChain cciptestinterfaces.ChainAsSource,
    destChain cciptestinterfaces.ChainAsDestination,
    fields cciptestinterfaces.MessageFields,
    opts cciptestinterfaces.MessageOptions,
    sendOption cciptestinterfaces.ChainSendOption,
) error
```

`evmPOC_test.go` is an end-to-end test that verifies `CCIP17EVM` satisfies both `ChainAsSource` and `ChainAsDestination` and runs a basic EVM→EVM message flow using `BasicMessageTestScenario`.

A `tests/composable/token/` directory is reserved (`.gitkeep`) for future token-transfer composable tests.

### Load test gun (`build/devenv/tests/e2e/gun.go`)

The load-test gun has been updated to use the new interfaces:

- `GetRoundRobinUser` and `GetUserNonce` are now accessed via a runtime `evm.EVMOptions` type assertion instead of being called directly on the `CCIP17` interface.
- Message sending now uses `ChainAsSource.BuildChainMessage` + `SendChainMessage` with `EVMSendOptions{DisableTokenAmountValidation: true}` instead of `SendMessageWithNonce`.
- `NewEVMTransactionGun` now returns `(*EVMTXGun, error)` to surface configuration errors early.

## Marker Interface pattern

Both `ChainSendOption` and `EVMOptions` use Go's **marker interface** pattern. The idea is to define a minimal interface — sometimes with a single dummy method, sometimes with no methods at all — whose sole purpose is to constrain what types can flow through a generic API at compile time, while leaving the actual family-specific dispatch to runtime type assertions.

### `ChainSendOption` — typed send parameters without generics

`ChainSendOption` is defined in `cciptestinterfaces`:

```go
type ChainSendOption interface {
    IsSendOption() bool
}
```

`IsSendOption()` carries no semantic information. It exists only so that the compiler rejects arbitrary values at the `SendChainMessage` call site — callers must pass something explicitly annotated as a send option, not just any `any`.

The EVM implementation satisfies the marker with a one-liner:

```go
// build/devenv/evm/interface.go
func (o EVMSendOptions) IsSendOption() bool { return true }
```

Inside `SendChainMessage`, the generic interface is narrowed to the concrete type via type assertion:

```go
// build/devenv/evm/impl.go
var evmOpts EVMSendOptions
if o, ok := sendOption.(EVMSendOptions); ok {
    evmOpts = o
}
// evmOpts is zero-valued (all defaults) if sendOption was nil or a different family's type.
```

This means:
- Shared scenario code (`BasicMessageTestScenario`, `BasicMessageTestScenario`, etc.) passes `sendOption` through without needing to know its concrete type.
- EVM's `SendChainMessage` extracts the EVM fields it cares about; a future Stellar implementation would assert to `StellarSendOptions` instead.
- Passing `nil` is valid and produces safe zero-value defaults — no nonce override, default sender, token amount validation enabled.

A new chain family adds send-option support in three steps:

```go
// 1. Define the family-specific options struct.
type StellarSendOptions struct {
    SequenceNumber *uint64
    // ...
}

// 2. Satisfy the marker interface.
func (o StellarSendOptions) IsSendOption() bool { return true }

// 3. Extract inside SendChainMessage.
var stellarOpts StellarSendOptions
if o, ok := sendOption.(StellarSendOptions); ok {
    stellarOpts = o
}
```

No changes to `cciptestinterfaces` or shared test helpers are required.

### `EVMOptions` — optional EVM capabilities via type assertion

`EVMOptions` is a different use of the same pattern, but without a marker method. It groups EVM-specific methods that were removed from the top-level `Chain` interface because they have no meaningful equivalent on other chain families:

```go
// build/devenv/evm/interface.go
type EVMOptions interface {
    GetRoundRobinUser() func() *bind.TransactOpts
    GetUserNonce(ctx context.Context, userAddress protocol.UnknownAddress) (uint64, error)
}
```

Code that needs these capabilities type-asserts at the point of use rather than declaring them on `Chain`:

```go
// build/devenv/tests/e2e/gun.go
if evmImpl, ok := impls[chain].(evm.EVMOptions); ok {
    userSelector[chain] = evmImpl.GetRoundRobinUser()
}
```

This keeps the shared `Chain` interface generic and forces EVM-specific callers to declare their dependency explicitly. If the assertion fails (e.g. in a future Stellar test environment), the caller can handle the absence gracefully or skip EVM-only load features entirely.

### Why not generics?

The alternative would be to parameterise `ChainAsSource` over the send-option type:

```go
type ChainAsSource[O ChainSendOption] interface {
    SendChainMessage(ctx context.Context, dest uint64, msg any, opt O) (MessageSentEvent, protocol.ByteSlice, error)
    // ...
}
```

This would catch option/implementation mismatches at compile time but forces every caller and scenario helper to carry the type parameter, making cross-family test composition harder (you cannot mix `ChainAsSource[EVMSendOptions]` and `ChainAsSource[StellarSendOptions]` in the same slice without an additional abstraction layer). The marker-interface approach keeps the shared layer free of type parameters at the cost of a single runtime assertion inside each family's `SendChainMessage`.

## Adoption guide

### Using the new interfaces in tests

Replace any direct call to `chain.SendMessageWithNonce(...)` with:

```go
srcChain, ok := chain.(cciptestinterfaces.ChainAsSource)
if !ok {
    t.Fatal("chain does not implement ChainAsSource")
}

msg, err := srcChain.BuildChainMessage(ctx, destSelector, fields, opts)
require.NoError(t, err)

sentEvent, txHash, err := srcChain.SendChainMessage(ctx, destSelector, msg, nil)
require.NoError(t, err)
```

Pass EVM-specific options via `evm.EVMSendOptions`:

```go
sentEvent, txHash, err := srcChain.SendChainMessage(ctx, destSelector, msg, evm.EVMSendOptions{
    Sender:                       myKey,
    Nonce:                        &nonce,
    DisableTokenAmountValidation: true,
})
```

### Implementing `ChainAsSource` for a new chain family

1. Implement `BuildChainMessage` to construct the family-specific message type (returned as `any`).
2. Implement `SendChainMessage` to submit the message, confirm on-chain, and return the `MessageSentEvent` plus raw transaction bytes.
3. Define a family-specific `SendOption` struct that satisfies `ChainSendOption`.
4. Use `BasicMessageTestScenario` (or build on top of it) — no changes needed to the shared scenario code.

## Deprecated APIs

| Symbol | Removed from | Replacement |
|---|---|---|
| `Chain.SendMessageWithNonce` | `cciptestinterfaces.Chain` | `ChainAsSource.BuildChainMessage` + `SendChainMessage` with `EVMSendOptions` |
| `Chain.GetUserNonce` | `cciptestinterfaces.Chain` | `evm.EVMOptions.GetUserNonce` (type-assert to `evm.EVMOptions`) |
| `Chain.GetRoundRobinUser` | `cciptestinterfaces.Chain` | `evm.EVMOptions.GetRoundRobinUser` (type-assert to `evm.EVMOptions`) |

`Chain.SendMessage` remains and is kept for backward compatibility — it now delegates internally to the new composable path.
