# TCAPI V3 send path: `SendConfig` and composable send APIs

## Executive Summary

- Migrates importable TCAPI test cases in `basic` and `token_transfer` from deprecated `Chain.SendMessage` to `BuildV3ExtraArgs` + `BuildChainMessage` + `SendChainMessage` via a shared `tcapi.SendV3Message` helper.
- Introduces `tcapi.SendConfig` so callers supply pair-level execution gas, destination-shaped extra-args parameters (`any`), and optional `ChainSendOption` without importing chain-family types into generic test code.
- Affects `build/devenv/tests/e2e/tcapi`, `tcapi/basic`, `tcapi/token_transfer`, and in-repo smoke tests that call `basic.All` / `token_transfer.All` / `All17`.
- Breaking: `basic.All`, all exported `basic.*` case constructors, `token_transfer.All`, `token_transfer.All17`, and `token_transfer.TokenTransfer` gain a final `tcapi.SendConfig` parameter. `tcapi.TestCase` (`Run` / `HavePrerequisites`) is unchanged.
- Behavior: TCAPI `Run` no longer calls `GetExpectedNextSequenceNumber`; `ConfirmSendOnSource` / `ConfirmExecOnDest` use `MessageEventKey{MessageID: ...}` from `SendV3Message` (aligns with `MessageV3TestScenario`).

## AI Adapter Index

The expected consumer of this changelog is an AI adapting a downstream repo. This table is its entry point: every symbol or behavior touched gets one row, with a grep pattern for finding consumer call sites and an anchor into the rest of this file for migration detail. The AI is expected to:

1. Read this table.
2. Run each `Search` pattern against the consumer repo.
3. For rows that produce hits, read **only** the linked `Section`. Skip rows with zero hits.
4. Treat any symbol *not* listed here as unchanged — do not load source for it.

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `basic.All` | signature-changed | `basic\.All\(` | `build/devenv/tests/e2e/tcapi/basic/v3.go:650` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `basic.CustomExecutor` | signature-changed | `basic\.CustomExecutor\(` | `build/devenv/tests/e2e/tcapi/basic/v3.go:154` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `basic.EOAReceiverDefaultVerifier` | signature-changed | `basic\.EOAReceiverDefaultVerifier\(` | `build/devenv/tests/e2e/tcapi/basic/v3.go:198` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `basic.EOAReceiverSecondaryVerifier` | signature-changed | `basic\.EOAReceiverSecondaryVerifier\(` | `build/devenv/tests/e2e/tcapi/basic/v3.go:249` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `basic.ReceiverSecondaryVerifierRequired` | signature-changed | `basic\.ReceiverSecondaryVerifierRequired\(` | `build/devenv/tests/e2e/tcapi/basic/v3.go:304` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `basic.ReceiverSecondaryRequiredTertiaryOptionalThreshold1` | signature-changed | `basic\.ReceiverSecondaryRequiredTertiaryOptionalThreshold1\(` | `build/devenv/tests/e2e/tcapi/basic/v3.go:348` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `basic.ReceiverQuaternaryAllThreeVerifiers` | signature-changed | `basic\.ReceiverQuaternaryAllThreeVerifiers\(` | `build/devenv/tests/e2e/tcapi/basic/v3.go:396` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `basic.ReceiverQuaternaryDefaultAndSecondary` | signature-changed | `basic\.ReceiverQuaternaryDefaultAndSecondary\(` | `build/devenv/tests/e2e/tcapi/basic/v3.go:447` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `basic.ReceiverQuaternaryDefaultAndTertiary` | signature-changed | `basic\.ReceiverQuaternaryDefaultAndTertiary\(` | `build/devenv/tests/e2e/tcapi/basic/v3.go:494` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `basic.MaxDataSize` | signature-changed | `basic\.MaxDataSize\(` | `build/devenv/tests/e2e/tcapi/basic/v3.go:541` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `basic.EOAReceiverDefaultVerifier_SafeTag` | signature-changed | `basic\.EOAReceiverDefaultVerifier_SafeTag\(` | `build/devenv/tests/e2e/tcapi/basic/v3.go:599` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `token_transfer.All` | signature-changed | `token_transfer\.All\(` | `build/devenv/tests/e2e/tcapi/token_transfer/v3.go:252` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `token_transfer.All17` | signature-changed | `token_transfer\.All17\(` | `build/devenv/tests/e2e/tcapi/token_transfer/v3.go:262` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `token_transfer.TokenTransfer` | signature-changed | `token_transfer\.TokenTransfer\(` | `build/devenv/tests/e2e/tcapi/token_transfer/v3.go:184` | [#basic-and-token-transfer-constructors](#basic-and-token-transfer-constructors) |
| `tcapi.SendConfig` | added | `\btcapi\.SendConfig\b` | `build/devenv/tests/e2e/tcapi/types.go:44` | [#sendconfig-and-sendv3message](#sendconfig-and-sendv3message) |
| `tcapi.DefaultV3ExecutionGasLimit` | added | `\bDefaultV3ExecutionGasLimit\b` | `build/devenv/tests/e2e/tcapi/types.go:40` | [#sendconfig-and-sendv3message](#sendconfig-and-sendv3message) |
| `tcapi.SendV3Message` | added | `\btcapi\.SendV3Message\(` | `build/devenv/tests/e2e/tcapi/types.go:52` | [#sendconfig-and-sendv3message](#sendconfig-and-sendv3message) |
| `tcapi.TestCase.Run` | unchanged | — | `build/devenv/tests/e2e/tcapi/types.go:29` | — |
| `tcapi.TestCase.HavePrerequisites` | unchanged | — | `build/devenv/tests/e2e/tcapi/types.go:36` | — |
| TCAPI `Run` confirm path (`GetExpectedNextSequenceNumber` removed) | behavior-changed | `GetExpectedNextSequenceNumber` in `tcapi/` | `build/devenv/tests/e2e/tcapi/basic/v3.go:52` | [#tcapi-confirm-by-message-id](#tcapi-confirm-by-message-id) |

## Breaking Changes

### Basic and token-transfer constructors

- **What changed:** Every `basic` case factory and `token_transfer` suite entry point now takes `cfg tcapi.SendConfig` as the last argument.
- **Before:**
  ```go
  basic.All(lib, srcSelector, destSelector)
  basic.EOAReceiverDefaultVerifier(lib, srcSelector, destSelector)
  token_transfer.All(lib, srcSelector, destSelector, combos)
  token_transfer.All17(lib, srcSelector, destSelector, combos)
  token_transfer.TokenTransfer(lib, src, dest, combo, finality, useEOA, name)
  ```
- **After:**
  ```go
  basic.All(lib, srcSelector, destSelector, cfg)
  basic.EOAReceiverDefaultVerifier(lib, srcSelector, destSelector, cfg)
  token_transfer.All(lib, srcSelector, destSelector, combos, cfg)
  token_transfer.All17(lib, srcSelector, destSelector, combos, cfg)
  token_transfer.TokenTransfer(lib, src, dest, combo, finality, useEOA, name, cfg)
  ```
- **Why:** Pair-specific V3 extra-args construction (gas limit, destination `GetExecutorArgs` / `GetTokenArgs` / `GetTokenReceiver` inputs) must be supplied by the test driver without embedding chain-family types inside generic TCAPI `Run` logic. `SendConfig` is threaded from `All()` or single-case constructors into each test case struct and consumed at send time after `hydrate` fills `MessageOptions` (executor, CCVs, etc.).
- **Who is affected:** Any downstream repo that imports `github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/basic` or `.../token_transfer` and calls the listed constructors. In-repo smoke tests updated at `build/devenv/tests/e2e/smoke_test.go`.

### TCAPI case send implementation (behavior, not public API)

- **What changed:** `v3TestCase.Run` and `tokenTransferV3TestCase.Run` no longer call `src.SendMessage(..., messageVersion 3)`.
- **After:** Both call `tcapi.SendV3Message`, which type-asserts `MessageV3Source` / `MessageV3Destination` / `ChainAsSource` and runs `BuildV3ExtraArgs` → `BuildChainMessage` → `SendChainMessage`.
- **Why:** Aligns importable tests with composable chain interfaces and removes dependence on deprecated `SendMessage` for the tcapi packages.
- **Who is affected:** Consumers relying on side effects of `SendMessage` inside TCAPI cases only; external callers of `TestCase.Run` see the same success/failure semantics for EVM→EVM with empty `SendConfig`.

### TCAPI confirm by message ID

- **What changed:** `v3TestCase.Run` and `tokenTransferV3TestCase.Run` no longer call `GetExpectedNextSequenceNumber` before send. After `tcapi.SendV3Message`, both `ConfirmSendOnSource` and `ConfirmExecOnDest` use `cciptestinterfaces.MessageEventKey{MessageID: sendResult.MessageID}` (same pattern as `messaging.MessageV3TestScenario`).
- **Before:** Pre-read expected sequence number; confirm send/exec with `MessageEventKey{SeqNum: seqNo}`; take `messageID` from `ConfirmSendOnSource` for aggregator asserts.
- **After:** `messageID` comes from `SendV3Message` / `SendChainMessage`; confirms key off that ID. Optional seq logging uses `sendResult.Message.SequenceNumber` when present.
- **Why:** Reduces required chain API surface for importable tests (`GetExpectedNextSequenceNumber` is on full `CCIP17` / `Chain`, not `ChainAsSource`). Avoids seq races when another message lands on the lane between pre-read and send. Matches composable messaging tests.
- **Who is affected:** Downstream code that assumed TCAPI cases depended on `GetExpectedNextSequenceNumber` (they no longer do). Other e2e tests outside `tcapi/basic` and `tcapi/token_transfer` are unchanged.

## Migration Guide

1. Add `tcapi` import if not already present:
   ```go
   "github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
   ```

2. Define pair-level send settings once per `(src, dest)` lane (or per test binary):
   ```go
   sendCfg := tcapi.SendConfig{} // EVM→EVM: default 200k gas, nil dest extra-args params
   ```

3. Pass `sendCfg` into suite constructors:
   ```go
   // Before
   cases := basic.All(lib, srcSel, destSel)

   // After
   cases := basic.All(lib, srcSel, destSel, sendCfg)
   ```

4. Update single-case constructors the same way:
   ```go
   // Before
   tc := basic.MaxDataSize(lib, srcSel, destSel)

   // After
   tc := basic.MaxDataSize(lib, srcSel, destSel, sendCfg)
   ```

5. For cross-family lanes (e.g. EVM source → Solana destination), populate `SendConfig` at the driver — not inside `basic` / `token_transfer` packages:
   ```go
   sendCfg := tcapi.SendConfig{
       ExecutionGasLimit: 500_000,
       ExtraArgsParams:     svmExecutorArgs, // type expected by dest GetExecutorArgs
   }
   cases := basic.All(lib, evmSel, solSel, sendCfg)
   ```
   Product repos own the concrete `ExtraArgsParams` / `TokenArgsParams` / `TokenReceiverParams` values; TCAPI `hydrate` remains EVM-centric for prerequisites until a separate change lands.

6. `Run` and `HavePrerequisites` are unchanged — no updates to subtest loops beyond constructor calls:
   ```go
   if tc.HavePrerequisites(ctx) {
       require.NoError(t, tc.Run(ctx))
   }
   ```

## New Features / Additions

### `SendConfig` and `SendV3Message`

- **`tcapi.SendConfig`** — pair-level settings for V3 sends in TCAPI tests. Fields: `ExecutionGasLimit` (0 → use `MessageOptions` if set, else `DefaultV3ExecutionGasLimit`), `ExtraArgsParams`, `TokenArgsParams`, `TokenReceiverParams` (passed through to `MessageV3Source.BuildV3ExtraArgs` and destination `Get*` methods), `SendOption` (`cciptestinterfaces.ChainSendOption` for `SendChainMessage`). See `build/devenv/tests/e2e/tcapi/types.go:44`.
- **`tcapi.DefaultV3ExecutionGasLimit`** — `200_000`; matches prior hardcoded gas in TCAPI `Run` methods. See `build/devenv/tests/e2e/tcapi/types.go:40`.
- **`tcapi.SendV3Message`** — shared helper: assert composable interfaces, merge gas from `SendConfig` / `MessageOptions`, `BuildV3ExtraArgs`, `BuildChainMessage`, `SendChainMessage`. See `build/devenv/tests/e2e/tcapi/types.go:52`.
  - Usage: optional direct use in custom test drivers; TCAPI `basic` and `token_transfer` already call it from `Run`.

## Compatibility & Requirements

- **Non-zero `MessageID` on send:** `MessageEventKey` requires either a non-zero `MessageID` or non-zero `SeqNum` (`cciptestinterfaces` validation in `ConfirmSendOnSource` / `ConfirmExecOnDest`). Every `ChainAsSource.SendChainMessage` implementation used with TCAPI must populate `MessageSentEvent.MessageID` on success. TCAPI `Run` returns an error if send succeeds but `MessageID` is zero. EVM does this from the tx receipt; verify Solana/Canton (and any new source) before running cross-family TCAPI suites.
- **`GetExpectedNextSequenceNumber`:** Still exists on `cciptestinterfaces.Chain` / `CCIP17` for other e2e tests; TCAPI importable cases no longer call it.
- **Confirm after send:** TCAPI still calls `ConfirmSendOnSource` after `SendV3Message` so log polling can observe the on-chain sent event (same as `MessageV3TestScenario`), even when the send path already returns `MessageID`.

## Examples

```go
// EVM→EVM smoke (behavior-neutral vs prior SendMessage path)
sendCfg := tcapi.SendConfig{}
for _, tc := range basic.All(lib, src.ChainSelector(), dest.ChainSelector(), sendCfg) {
    if tc.HavePrerequisites(ctx) {
        require.NoError(t, tc.Run(ctx))
    }
}
```

```go
// Single imported case with default pair config
tc := basic.EOAReceiverDefaultVerifier(lib, srcSel, destSel, tcapi.SendConfig{})
require.NoError(t, tc.Run(ctx))
```

## References

- Prior changelog entries: `changelog/2026-04-27_extra_args_data_provider.md`, `changelog/2026-05-18_simplify_tcapi.md`
- Composable send/confirm reference: `build/devenv/tests/composable/messaging/agnostic_chain_test.go` (`MessageV3TestScenario` uses `MessageEventKey{MessageID: sentEvent.MessageID}`)
