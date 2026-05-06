# Token receiver in Generic Extra Args V3 (`MessageOptions` / `MessageV3*` interfaces)

## Executive Summary

- Adds an optional **token receiver** address (`[]byte`) to `cciptestinterfaces.MessageOptions`, alongside executor and token args, for V3 messages where the token receiver may differ from the message receiver.
- Extends **destination** and **source** V3 interfaces: `MessageV3Destination` gains `GetTokenReceiver`; `MessageV3Source.BuildV3ExtraArgs` gains a `tokenReceiverParams` argument and `(*evm.CCIP17EVM).BuildV3ExtraArgs` pulls token receiver bytes from the destination before serialization.
- **Breaking** for any downstream type that implements `MessageV3Destination` or `MessageV3Source`, and for every call site of `BuildV3ExtraArgs`.
- **Wire note:** `SerializeMessageV3ExtraArgs` still invokes `NewV3ExtraArgs` without forwarding `opts.TokenReceiver`, and `NewV3ExtraArgs` still emits a **zero-length** token receiver segment (`build/devenv/evm/operations.go`); non-empty token receivers require a follow-up in that path.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `cciptestinterfaces.MessageV3Source.BuildV3ExtraArgs` | signature-changed | `BuildV3ExtraArgs\(` | `build/devenv/cciptestinterfaces/extra_args.go:60` | [#buildv3extraargs-signature](#buildv3extraargs-signature) |
| `evm.CCIP17EVM.BuildV3ExtraArgs` | signature-changed | `func \(m \*CCIP17EVM\) BuildV3ExtraArgs` | `build/devenv/evm/impl.go:2083` | [#ccip17evm-buildv3extraargs](#ccip17evm-buildv3extraargs) |
| `cciptestinterfaces.MessageV3Destination.GetTokenReceiver` | added | `GetTokenReceiver\(` | `build/devenv/cciptestinterfaces/extra_args.go:49` | [#messagev3destination-gettokenreceiver](#messagev3destination-gettokenreceiver) |
| `cciptestinterfaces.MessageOptions.TokenReceiver` | added | `opts\.TokenReceiver\b|TokenReceiver\s+\[\]byte` | `build/devenv/cciptestinterfaces/extra_args.go:24` | [#messageoptions-tokenreceiver](#messageoptions-tokenreceiver) |
| `cciptestinterfaces.MessageV3TokenReceiver` | added | `\bMessageV3TokenReceiver\b` | `build/devenv/cciptestinterfaces/extra_args.go:39` | [#messagev3tokenreceiver-type](#messagev3tokenreceiver-type) |
| `evm.CCIP17EVM.GetTokenReceiver` | added | `func \(m \*CCIP17EVM\) GetTokenReceiver` | `build/devenv/evm/impl.go:2122` | [#ccip17evm-gettokenreceiver](#ccip17evm-gettokenreceiver) |

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

## Migration Guide

1. **Implement `GetTokenReceiver`** on each `MessageV3Destination` implementer.
   - Return `nil, nil` if there is no distinct token receiver (matches current `(*evm.CCIP17EVM).GetTokenReceiver` stub at `build/devenv/evm/impl.go:2122`).
   - Type-assert `opts` the same way you do for `GetExecutorArgs` / `GetTokenArgs`.
2. **Update `BuildV3ExtraArgs` signatures** on each `MessageV3Source` implementer to accept `tokenReceiverParams any` and pass it into `destChain.GetTokenReceiver(tokenReceiverParams)`.
3. **Update call sites** to pass the new argument (e.g. `executorArgsParams`, `tokenReceiverParams`, `tokenArgsParams` — choose `nil` or a dedicated params object per destination conventions).
4. **Encoding path:** If you need a **non-empty** token receiver on-chain, verify `SerializeMessageV3ExtraArgs` / `NewV3ExtraArgs` forward `opts.TokenReceiver`; on this branch they do not yet do so (see Executive Summary).

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

- **`MessageOptions.TokenReceiver`** — optional raw token receiver address bytes for V3 extra-args composition. See `build/devenv/cciptestinterfaces/extra_args.go:24`.
  - Usage: populated by `(*evm.CCIP17EVM).BuildV3ExtraArgs` from `destChain.GetTokenReceiver(...)` before calling `SerializeMessageV3ExtraArgs` (`build/devenv/evm/impl.go:2102`).

<a id="messagev3tokenreceiver-type"></a>

- **`MessageV3TokenReceiver`** — named `[]byte` alias for destination-returned token receiver bytes. See `build/devenv/cciptestinterfaces/extra_args.go:39`.

<a id="ccip17evm-gettokenreceiver"></a>

- **`(*evm.CCIP17EVM).GetTokenReceiver`** — stub implementation returning `nil, nil` until a concrete token-receiver source is wired. See `build/devenv/evm/impl.go:2122`.

## Compatibility & Requirements

- **EVM / Canton V3 serialization:** `NewV3ExtraArgs` already reserves the GenericExtraArgsV3 token-receiver segment but currently writes **length 0** (`build/devenv/evm/operations.go:207`). `SerializeMessageV3ExtraArgs` does not pass `opts.TokenReceiver` into `NewV3ExtraArgs` (`build/devenv/evm/impl.go:794`), so setting `MessageOptions.TokenReceiver` via `BuildV3ExtraArgs` does not change encoded bytes until that wiring lands.

## References

- Branch: `jh/add-token-receiver-to-generic-extra-arg-v3` (commits: `005b3bd2`, `ccdc795e`).
- Add GitHub PR / design doc links here when available.
