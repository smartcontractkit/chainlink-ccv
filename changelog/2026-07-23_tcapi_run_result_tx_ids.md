# tcapi run results expose source/destination transaction ids with events

## Executive Summary

- Lets chain-family e2e tests pull the source send tx and destination exec tx (plus their chain-agnostic events) out of a tcapi run, for chain/tx-specific assertions the portable layer cannot own.
- Motivated by cross-family tests (EVM to Solana) that need to read on-chain pool CPI events from the exact execution tx.
- Affects `cciptestinterfaces` (the `Chain` / `ChainAsDestination` interfaces plus new envelope types) and `tcapi` (`TestCase.Run`, `RunResult`). Any implementer or caller of `ConfirmExecOnDest`, any implementer or caller of `TestCase.Run`, and any caller of `tcapi.SendV3Message` must update.
- Breaking: `ConfirmExecOnDest` now returns an `ExecEnvelope` (event plus opaque tx id) instead of a bare event; `TestCase.Run` now returns `(RunResult, error)` instead of `error`; `tcapi.SendV3Message` gains a `protocol.ByteSlice` (tx id) return value.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
| --- | --- | --- | --- | --- |
| `cciptestinterfaces.Chain.ConfirmExecOnDest` | signature-changed | `\.ConfirmExecOnDest\(` | `build/devenv/cciptestinterfaces/interface.go:166` | [#confirmexecondest-returns-an-execenvelope](#confirmexecondest-returns-an-execenvelope) |
| `tcapi.TestCase.Run` | signature-changed | `Run\(ctx context.Context\)` | `build/devenv/tests/e2e/tcapi/types.go:30` | [#testcaserun-returns-a-runresult](#testcaserun-returns-a-runresult) |
| `tcapi.SendV3Message` | signature-changed | `\.SendV3Message\(` | `build/devenv/tests/e2e/tcapi/types.go:105` | [#sendv3message-gains-a-tx-id-return](#sendv3message-gains-a-tx-id-return) |
| `cciptestinterfaces.ExecutionStateChangedEvent.SourceChainSelector` | behavior-changed | `\.SourceChainSelector\b` | `build/devenv/evm/impl.go:290` | [#sourcechainselector-now-populated-on-evm-exec-events](#sourcechainselector-now-populated-on-evm-exec-events) |
| `tcapi/token_transfer` receiver/balance handling | behavior-changed | `TokenReceiverParams\b` | `build/devenv/tests/e2e/tcapi/token_transfer/v3.go` | [#token-transfer-balance-checks-the-token-receiver](#token-transfer-balance-checks-the-token-receiver) |
| `cciptestinterfaces.SentEnvelope` | added | `\bSentEnvelope\b` | `build/devenv/cciptestinterfaces/interface.go:95` | [#runresult-and-envelope-types](#runresult-and-envelope-types) |
| `cciptestinterfaces.ExecEnvelope` | added | `\bExecEnvelope\b` | `build/devenv/cciptestinterfaces/interface.go:138` | [#runresult-and-envelope-types](#runresult-and-envelope-types) |
| `tcapi.RunResult` | added | `\bRunResult\b` | `build/devenv/tests/e2e/tcapi/types.go:74` | [#runresult-and-envelope-types](#runresult-and-envelope-types) |

## Breaking Changes

### ConfirmExecOnDest returns an ExecEnvelope

- **What changed:** `ConfirmExecOnDest` on the `cciptestinterfaces.Chain` and `cciptestinterfaces.ChainAsDestination` interfaces (impl: `build/devenv/evm/impl.go:433`).
- **Before:** `ConfirmExecOnDest(ctx, from, key, timeout) (ExecutionStateChangedEvent, error)`
- **After:** `ConfirmExecOnDest(ctx, from, key, timeout) (ExecEnvelope, error)`
- **Why:** return the execution event and its opaque destination tx id together in one value, rather than adding a separate bare tx-id return. The tx id lets chain-family tests locate and inspect the exec tx (for example, read pool CPI events from it).
- **Who is affected:** every implementer of the interface and every call site. Read the event via `env.Event` and the tx id via `env.TxID`. Implementations that cannot expose a tx id may leave `TxID` nil.

### TestCase.Run returns a RunResult

- **What changed:** `tcapi.TestCase.Run`. The separate `ObservableTestCase` interface and its `RunWithResult` method are removed; `Run` returns the result directly.
- **Before:** `Run(ctx) error`
- **After:** `Run(ctx) (RunResult, error)`
- **Why:** every case already produced a `RunResult` internally, so a second interface plus method to expose it was redundant.
- **Who is affected:** every caller of `Run`. Callers that only need pass/fail use `_, err := tc.Run(ctx)`; callers that need the source/destination evidence read the returned `RunResult`, with no type assertion.

### SendV3Message gains a tx-id return

- **What changed:** `tcapi.SendV3Message`.
- **Before:** `SendV3Message(...) (cciptestinterfaces.MessageSentEvent, error)`
- **After:** `SendV3Message(...) (cciptestinterfaces.MessageSentEvent, protocol.ByteSlice, error)`
- **Why:** surface the source send tx id alongside the sent event (it was already available from `SendChainMessage` and previously discarded).
- **Who is affected:** every caller of `tcapi.SendV3Message`.

## Migration Guide

1. Update `ConfirmExecOnDest` call sites to the envelope:

```go
// Before
execEvt, err := dest.ConfirmExecOnDest(ctx, src, key, timeout)
// After
execEnv, err := dest.ConfirmExecOnDest(ctx, src, key, timeout)
execEvt := execEnv.Event // execEnv.TxID holds the opaque tx id
```

2. Update `Chain` implementations to return an `ExecEnvelope` (leave `TxID` nil when the chain cannot expose one):

```go
// After
return cciptestinterfaces.ExecEnvelope{Event: execEvt, TxID: txID}, nil
```

3. Update `Run` call sites:

```go
// Before
require.NoError(t, tc.Run(ctx))
// After
_, err := tc.Run(ctx)
require.NoError(t, err)
```

4. Replace `ObservableTestCase` / `RunWithResult` with `Run`:

```go
// Before
res, err := tc.(tcapi.ObservableTestCase).RunWithResult(ctx)
// After
res, err := tc.Run(ctx)
```

5. Update `SendV3Message` call sites (use `_` when the tx id is not needed):

```go
// Before
sent, err := tcapi.SendV3Message(ctx, src, dst, fields, opts, args)
// After
sent, _, err := tcapi.SendV3Message(ctx, src, dst, fields, opts, args)
```

## New Features / Additions

### RunResult and envelope types

- **`tcapi.RunResult{ Src cciptestinterfaces.SentEnvelope; Dest cciptestinterfaces.ExecEnvelope }`**: portable evidence returned by a run. `SentEnvelope` and `ExecEnvelope` pair the chain-agnostic event with its opaque `TxID protocol.ByteSlice`.
  - Usage: a chain-family test reads `res.Dest.TxID` to fetch the exec tx and run chain-specific assertions (pool events, receiver state) that tcapi itself stays out of.

## Behavior Changes

### SourceChainSelector now populated on EVM exec events

- The EVM off-ramp poller now sets `ExecutionStateChangedEvent.SourceChainSelector` from the on-chain event (`build/devenv/evm/impl.go:290`). The field already existed and Solana's `ConfirmExecOnDest` already populated it; EVM previously left it as the zero value. Consumers may now assert on it for EVM-sourced executions.

### Token-transfer balance checks the token receiver

- `tcapi/token_transfer` v3 cases assert destination balances against the resolved token-receiver address (`tc.tokenReceiver`, falling back to the message receiver when no token receiver is supplied) instead of always the message receiver. When a separate token receiver is carried, the message receiver is left empty so destination chains that treat a non-zero receiver as an arbitrary-message delivery do not attempt a receiver CPI for a payload-less transfer.

## References

- PR: [github.com/smartcontractkit/chainlink-ccv#1289](https://github.com/smartcontractkit/chainlink-ccv/pull/1289)
- Related: [github.com/smartcontractkit/chainlink-ccip-solana#272](https://github.com/smartcontractkit/chainlink-ccip-solana/pull/272)
