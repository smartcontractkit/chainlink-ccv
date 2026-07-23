# tcapi run results expose source/destination transaction hashes

## Executive Summary

- Adds an opt-in way for chain-family e2e tests to pull the source send tx and destination exec tx (plus their chain-agnostic events) out of a tcapi run, for chain/tx-specific assertions the portable layer can't own.
- Motivated by cross-family tests (EVM to Solana) that need to read on-chain pool CPI events from the exact execution tx.
- Affects `cciptestinterfaces` (the `Chain` interface + new envelope types) and `tcapi` (`RunResult` / `RunWithResult` / `ObservableTestCase`). Any implementer or caller of `Chain.ConfirmExecOnDest`, and any caller of `tcapi.SendV3Message`, must update.
- Breaking: `Chain.ConfirmExecOnDest` and `tcapi.SendV3Message` each gain a `protocol.ByteSlice` (tx hash) return value. Everything else is additive.

## AI Adapter Index

| Symbol                                                              | Kind              | Search                    | Location                                                | Section                                                                                                        |
| ------------------------------------------------------------------- | ----------------- | ------------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `cciptestinterfaces.Chain.ConfirmExecOnDest`                        | signature-changed | `\.ConfirmExecOnDest\(`   | `build/devenv/cciptestinterfaces/interface.go:166`      | [#confirmexecondest-gains-a-tx-hash-return](#confirmexecondest-gains-a-tx-hash-return)                         |
| `tcapi.SendV3Message`                                               | signature-changed | `\.SendV3Message\(`       | `build/devenv/tests/e2e/tcapi/types.go:105`             | [#sendv3message-gains-a-tx-hash-return](#sendv3message-gains-a-tx-hash-return)                                 |
| `cciptestinterfaces.ExecutionStateChangedEvent.SourceChainSelector` | behavior-changed  | `\.SourceChainSelector\b` | `build/devenv/evm/impl.go:290`                          | [#sourcechainselector-now-populated-on-evm-exec-events](#sourcechainselector-now-populated-on-evm-exec-events) |
| `tcapi/token_transfer` receiver/balance handling                    | behavior-changed  | `TokenReceiverParams\b`   | `build/devenv/tests/e2e/tcapi/token_transfer/v3.go:293` | [#token-transfer-balance-checks-the-token-receiver](#token-transfer-balance-checks-the-token-receiver)         |
| `cciptestinterfaces.SentEnvelope`                                   | added             | `\bSentEnvelope\b`        | `build/devenv/cciptestinterfaces/interface.go:95`       | [#runresult-and-envelope-types](#runresult-and-envelope-types)                                                 |
| `cciptestinterfaces.ExecEnvelope`                                   | added             | `\bExecEnvelope\b`        | `build/devenv/cciptestinterfaces/interface.go:138`      | [#runresult-and-envelope-types](#runresult-and-envelope-types)                                                 |
| `tcapi.RunResult`                                                   | added             | `\bRunResult\b`           | `build/devenv/tests/e2e/tcapi/types.go:74`              | [#runresult-and-envelope-types](#runresult-and-envelope-types)                                                 |
| `tcapi.ObservableTestCase`                                          | added             | `\bObservableTestCase\b`  | `build/devenv/tests/e2e/tcapi/types.go:52`              | [#observabletestcase-and-runwithresult](#observabletestcase-and-runwithresult)                                 |
| `tcapi.ObservableTestCase.RunWithResult`                            | added             | `\.RunWithResult\(`       | `build/devenv/tests/e2e/tcapi/types.go:57`              | [#observabletestcase-and-runwithresult](#observabletestcase-and-runwithresult)                                 |

## Breaking Changes

### ConfirmExecOnDest gains a tx-hash return

- **What changed:** `ConfirmExecOnDest` on the `cciptestinterfaces.Chain` and `cciptestinterfaces.ChainAsDestination` interfaces (impl: `build/devenv/evm/impl.go:433`).
- **Before:** `ConfirmExecOnDest(ctx, from, key, timeout) (ExecutionStateChangedEvent, error)`
- **After:** `ConfirmExecOnDest(ctx, from, key, timeout) (ExecutionStateChangedEvent, protocol.ByteSlice, error)`
- **Why:** expose the destination execution tx id so chain-family tests can locate and inspect the exec tx (e.g. read pool CPI events from it).
- **Who is affected:** every implementer of the interface and every call site. The tx id is opaque (EVM tx hash, Solana signature, etc.); implementations that cannot expose one may return `nil`.

### SendV3Message gains a tx-hash return

- **What changed:** `tcapi.SendV3Message`.
- **Before:** `SendV3Message(...) (cciptestinterfaces.MessageSentEvent, error)`
- **After:** `SendV3Message(...) (cciptestinterfaces.MessageSentEvent, protocol.ByteSlice, error)`
- **Why:** surface the source send tx id alongside the sent event (it was already available from `SendChainMessage` and previously discarded).
- **Who is affected:** every caller of `tcapi.SendV3Message`.

## Migration Guide

1. Update `ConfirmExecOnDest` call sites to accept the new return value (use `_` when the tx id is not needed):

```go
// Before
execEvt, err := dest.ConfirmExecOnDest(ctx, src, key, timeout)
// After
execEvt, _, err := dest.ConfirmExecOnDest(ctx, src, key, timeout)
```

2. Update `Chain` implementations to return the tx id (or `nil` if the chain cannot expose it):

```go
// After
return execEvt, protocol.ByteSlice(txSig[:]), nil
```

3. Update `SendV3Message` call sites the same way:

```go
// Before
sent, err := tcapi.SendV3Message(ctx, src, dst, fields, opts, args)
// After
sent, _, err := tcapi.SendV3Message(ctx, src, dst, fields, opts, args)
```

## New Features / Additions

### RunResult and envelope types

- **`tcapi.RunResult{ Src cciptestinterfaces.SentEnvelope; Dest cciptestinterfaces.ExecEnvelope }`** — portable evidence returned by a run. `SentEnvelope` / `ExecEnvelope` pair the chain-agnostic event with its opaque `TxHash protocol.ByteSlice`.
  - Usage: a chain-family test reads `res.Dest.TxHash` to fetch the exec tx and run chain-specific assertions (pool events, receiver state) that tcapi itself stays out of.

### ObservableTestCase and RunWithResult

- **`tcapi.ObservableTestCase`** — optional interface (`TestCase` + `RunWithResult(ctx) (RunResult, error)`), implemented by the basic and token-transfer v3 cases. `Run` now delegates to `RunWithResult`, so existing `Run` callers are unchanged.
  - Usage: type-assert a case to `ObservableTestCase` and call `RunWithResult` to get the source/destination tx evidence.

## Behavior Changes

### SourceChainSelector now populated on EVM exec events

- The EVM off-ramp poller now sets `ExecutionStateChangedEvent.SourceChainSelector` from the on-chain event (`build/devenv/evm/impl.go:290`). The field already existed and Solana's `ConfirmExecOnDest` already populated it; EVM previously left it as the zero value. Consumers may now assert on it for EVM-sourced executions.

### Token-transfer balance checks the token receiver

- `tcapi/token_transfer` v3 cases now assert destination balances against the resolved token-receiver address (`tc.tokenReceiver`, falling back to the message receiver when no token receiver is supplied) instead of always the message receiver. When a separate token receiver is carried, the message receiver is left empty so destination chains that treat a non-zero receiver as an arbitrary-message delivery do not attempt a receiver CPI for a payload-less transfer.

## References

- PR: [github.com/smartcontractkit/chainlink-ccv#1289](https://github.com/smartcontractkit/chainlink-ccv/pull/1289)
- Related: [github.com/smartcontractkit/chainlink-ccip-solana#272](https://github.com/smartcontractkit/chainlink-ccip-solana/pull/272)
