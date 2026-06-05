# Token receiver in Generic Extra Args V3 (`MessageOptions` / `MessageV3*` interfaces)

## Executive Summary

- Adds an optional **token receiver** payload (`[]byte`) to `cciptestinterfaces.MessageOptions`, alongside executor and token args, for V3 messages where the token receiver may differ from the message receiver (opaque bytes — EVM address length, Solana pubkey length, etc.).
- Extends **destination** and **source** V3 interfaces: `MessageV3Destination` gains `GetTokenReceiver`; `MessageV3Source.BuildV3ExtraArgs` gains a `tokenReceiverParams` argument and `(*evm.CCIP17EVM).BuildV3ExtraArgs` pulls token receiver bytes from the destination before serialization.
- **Breaking** for any downstream type that implements `MessageV3Destination` or `MessageV3Source`, and for every call site of `BuildV3ExtraArgs`.
- **Wire:** `SerializeMessageV3ExtraArgs` passes `opts.TokenReceiver` into `NewV3ExtraArgs`, which encodes it as **uint8 length + payload** (max **255** bytes), matching `ExtraArgsCodec._writeUint8PrefixedBytes` in `chainlink-ccip/chains/evm/contracts/libraries/ExtraArgsCodec.sol` (`_encodeGenericExtraArgsV3`).

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `cciptestinterfaces.MessageV3Source.BuildV3ExtraArgs` | signature-changed | `BuildV3ExtraArgs\(` | `build/devenv/cciptestinterfaces/extra_args.go:60` | [#buildv3extraargs-signature](#buildv3extraargs-signature) |
| `evm.CCIP17EVM.BuildV3ExtraArgs` | signature-changed | `func \(m \*CCIP17EVM\) BuildV3ExtraArgs` | `build/devenv/evm/impl.go:2084` | [#ccip17evm-buildv3extraargs](#ccip17evm-buildv3extraargs) |
| `evm.NewV3ExtraArgs` | behavior-changed | `func NewV3ExtraArgs\(` | `build/devenv/evm/operations.go:125` | [#newv3extraargs-tokenreceiver-wire](#newv3extraargs-tokenreceiver-wire) |
| `evm.SerializeMessageV3ExtraArgs` | behavior-changed | `func SerializeMessageV3ExtraArgs\(` | `build/devenv/evm/impl.go:789` | [#serializemessagev3-tokenreceiver](#serializemessagev3-tokenreceiver) |
| `cciptestinterfaces.MessageV3Destination.GetTokenReceiver` | added | `GetTokenReceiver\(` | `build/devenv/cciptestinterfaces/extra_args.go:49` | [#messagev3destination-gettokenreceiver](#messagev3destination-gettokenreceiver) |
| `cciptestinterfaces.MessageOptions.TokenReceiver` | added | `opts\.TokenReceiver\b|TokenReceiver\s+\[\]byte` | `build/devenv/cciptestinterfaces/extra_args.go:24` | [#messageoptions-tokenreceiver](#messageoptions-tokenreceiver) |
| `cciptestinterfaces.MessageV3TokenReceiver` | added | `\bMessageV3TokenReceiver\b` | `build/devenv/cciptestinterfaces/extra_args.go:39` | [#messagev3tokenreceiver-type](#messagev3tokenreceiver-type) |
| `evm.CCIP17EVM.GetTokenReceiver` | added | `func \(m \*CCIP17EVM\) GetTokenReceiver` | `build/devenv/evm/impl.go:2123` | [#ccip17evm-gettokenreceiver](#ccip17evm-gettokenreceiver) |
| `evm.MaxTokenReceiverLength` | added | `\bMaxTokenReceiverLength\b` | `build/devenv/evm/operations.go:121` | [#maxtokenreceiverlength](#maxtokenreceiverlength) |

## Breaking Changes

<a id="buildv3extraargs-signature"></a>
<a id="ccip17evm-buildv3extraargs"></a>

### `BuildV3ExtraArgs` takes `tokenReceiverParams`

- **What changed:** `MessageV3Source.BuildV3ExtraArgs` now accepts `tokenReceiverParams any` between `executorArgsParams` and `tokenArgsParams`.
- **Before:** `BuildV3ExtraArgs(opts, destChain, executorArgsParams, tokenArgsParams)`
- **After:** `BuildV3ExtraArgs(opts, destChain, executorArgsParams, tokenReceiverParams, tokenArgsParams)`
- **Why:** Allows the destination to supply token-receiver bytes independently of token args when building V3 extra args.
- **Who is affected:** All implementations of `MessageV3Source` and every caller of `BuildV3ExtraArgs`.

<a id="messagev3destination-gettokenreceiver"></a>

### `MessageV3Destination` requires `GetTokenReceiver`

- **What changed:** Implementers of `MessageV3Destination` must implement `GetTokenReceiver(opts any) (MessageV3TokenReceiver, error)`.
- **Before:** Interface had only `GetExecutorArgs` and `GetTokenArgs`.
- **After:** Interface also requires `GetTokenReceiver`.
- **Why:** Token receiver is modeled explicitly for V3 generic extra args.
- **Who is affected:** Every concrete destination type that satisfied `MessageV3Destination` before this change.

<a id="newv3extraargs-tokenreceiver-wire"></a>
<a id="serializemessagev3-tokenreceiver"></a>

### GenericExtraArgsV3 token receiver on the wire (`NewV3ExtraArgs` / `SerializeMessageV3ExtraArgs`)

- **What changed:** `tokenReceiver` is encoded as **uint8 length + opaque payload** (same as Solidity `_writeUint8PrefixedBytes`), not a hard-coded empty segment and not fixed to 20 bytes.
- **`SerializeMessageV3ExtraArgs`:** passes `opts.TokenReceiver` into `NewV3ExtraArgs` (`build/devenv/evm/impl.go:794`).
- **`NewV3ExtraArgs`:** rejects `len(tokenReceiver) > MaxTokenReceiverLength` (255); otherwise writes `uint8(len)` then bytes (`build/devenv/evm/operations.go:212`).
- **Who is affected:** Any consumer that assumed the token-receiver segment was always empty or EVM-20-byte-only in Go-encoded V3 extra args; integrators passing non-empty `MessageOptions.TokenReceiver` now affect on-chain bytes.

## Migration Guide

1. **Implement `GetTokenReceiver`** on each `MessageV3Destination` implementer.
   - Return `nil, nil` if there is no distinct token receiver (matches current `(*evm.CCIP17EVM).GetTokenReceiver` stub at `build/devenv/evm/impl.go:2123`).
   - Type-assert `opts` the same way you do for `GetExecutorArgs` / `GetTokenArgs`.
2. **Update `BuildV3ExtraArgs` signatures** on each `MessageV3Source` implementer to accept `tokenReceiverParams any` and pass it into `destChain.GetTokenReceiver(tokenReceiverParams)`.
3. **Update call sites** to pass the new argument (e.g. `executorArgsParams`, `tokenReceiverParams`, `tokenArgsParams` — choose `nil` or a dedicated params object per destination conventions).
4. **Payload size:** When setting `MessageOptions.TokenReceiver` (or returning bytes from `GetTokenReceiver`), keep length **≤ 255** bytes — the V3 codec uses a **uint8** length prefix (`build/devenv/evm/operations.go`, `ExtraArgsCodec.sol`).

### Example (call site)

```go
// Before
extraArgs, err := v3Source.BuildV3ExtraArgs(opts, v3Receiver, executorArgsParams, tokenArgsParams)

// After
extraArgs, err := v3Source.BuildV3ExtraArgs(opts, v3Receiver, executorArgsParams, tokenReceiverParams, tokenArgsParams)
```

### Example (`MessageV3Destination` stub)

```go
func (d *MyDest) GetTokenReceiver(_ any) (cciptestinterfaces.MessageV3TokenReceiver, error) {
	return nil, nil
}
```

## New Features / Additions

<a id="messageoptions-tokenreceiver"></a>

- **`MessageOptions.TokenReceiver`** — optional opaque token receiver bytes for V3 extra-args composition. See `build/devenv/cciptestinterfaces/extra_args.go:24`.
  - Usage: populated by `(*evm.CCIP17EVM).BuildV3ExtraArgs` from `destChain.GetTokenReceiver(...)` before calling `SerializeMessageV3ExtraArgs` (`build/devenv/evm/impl.go:2103`), which forwards `opts.TokenReceiver` into `NewV3ExtraArgs` (`impl.go:799`).

<a id="messagev3tokenreceiver-type"></a>

- **`MessageV3TokenReceiver`** — named `[]byte` alias for destination-returned token receiver bytes. See `build/devenv/cciptestinterfaces/extra_args.go:39`.

<a id="ccip17evm-gettokenreceiver"></a>

- **`(*evm.CCIP17EVM).GetTokenReceiver`** — stub implementation returning `nil, nil` until a concrete token-receiver source is wired. See `build/devenv/evm/impl.go:2123`.

<a id="maxtokenreceiverlength"></a>

- **`MaxTokenReceiverLength`** — `255`; maximum `tokenReceiver` payload size for GenericExtraArgsV3 (`build/devenv/evm/operations.go:121`).

## Compatibility & Requirements

- **Solidity parity:** Token receiver segment matches `_writeUint8PrefixedBytes(extraArgs.tokenReceiver)` in `ExtraArgsCodec._encodeGenericExtraArgsV3` / `_decodeGenericExtraArgsV3`.
- **Executor / CCV addresses** in `NewV3ExtraArgs` remain **uint8-prefixed EVM addresses** (0 or 20 bytes), unchanged from prior behavior.
- **Regression tests (optional for downstream):** `build/devenv/evm/operations_test.go` — test-only `decodeNewV3ExtraArgs` round-trips `NewV3ExtraArgs` bytes into `cciptestinterfaces.MessageOptions`. Run from the `build/devenv` module: `go test ./evm -run TestNewV3ExtraArgs`.

## References

- Branch: `jh/add-token-receiver-to-generic-extra-arg-v3` (initial commits: `005b3bd2`, `ccdc795e`; subsequent wiring/tests may add further commits).
- Add GitHub PR / design doc links here when available.
