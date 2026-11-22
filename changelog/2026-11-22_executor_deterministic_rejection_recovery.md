# Executor deterministic rejection recovery

## Executive Summary

- Standalone TXM v2 now discards deterministic first-broadcast gas rejections and immediately reuses their nonces, restoring TXM v1 behavior instead of waiting for AutoPurge.
- Both `intrinsic gas too low` and geth's `insufficient gas for floor data gas cost` are recognized, including backend-specific suffixes.
- `executor_txm_discarded_transactions_total{chainID}` counts discards, and discard logs include CCIP message IDs from TXM metadata.
- AutoPurge remains the backstop for later attempts, mempool-stuck transactions, and unmatched deterministic failures such as the per-transaction gas cap.
- No transmitter gas estimation or additional gas top-up is introduced by this change. Testnet retains its separate `LimitMultiplier = 2` stopgap while the backlog drains; no mainnet multiplier is prescribed.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evm.deterministicTxErrorHandler.HandleError` | added | `deterministicTxErrorHandler` | `integration/pkg/accessors/evm/txm_error_handler.go:16` | [#deterministic-rejection-handling](#deterministic-rejection-handling) |
| `evm.newCCVTxmMetrics` | added | `newCCVTxmMetrics\(` | `integration/pkg/accessors/evm/txm_metrics.go:25` | [#discard-observability](#discard-observability) |
| `evm.newTxmV2` | behavior-changed | `newTxmV2\(` | `integration/pkg/accessors/evm/txm.go:49` | [#deterministic-rejection-handling](#deterministic-rejection-handling) |

## Breaking Changes

*No breaking changes.* The change is internal to standalone TXM v2 construction and does not alter the executor or transmitter APIs.

## Deterministic rejection handling

`newTxmV2` installs `deterministicTxErrorHandler` instead of a nil error handler. It handles only a transaction's first broadcast, when rewinding the just-assigned nonce cannot collide with subsequent in-flight transactions.

The handler calls `MarkTxFatal`, rewinds that nonce, and lets the next transaction reuse it. A rejected transaction leaves nothing on-chain, so later executor turns no longer leave a sequence of stuck heads behind them.

Later attempts are deliberately ineligible: rewinding then could collide with subsequent nonces. Unrelated RPC errors are also left to normal TXM handling. AutoPurge remains available for those later attempts, mempool-stuck transactions, and other deterministic failures.

## Discard observability

`newCCVTxmMetrics` wraps the standard TXM metrics without changing the upstream interface. Each discard increments `executor_txm_discarded_transactions_total` with a `chainID` label, and the log includes `txID`, `nonce`, `messageIDs`, and the RPC error. Metric initialization failure degrades to log-only behavior without preventing recovery.

## Recovery

`docs/runbooks/evm-executor-gas-recovery.md` describes:

- The testnet-only `LimitMultiplier = 2` stopgap for draining stale Solana messages.
- AutoPurge with a positive threshold and an eight-hour rediscovery window.
- Immediate first-broadcast recovery from the fixed release and controlled canary/fleet restarts.
- The full Solana Glamsterdam migration required for correct pricing and execution of new messages, plus manual handling for messages older than eight hours.

Do not carry the multiplier into mainnet configuration before product decides the appropriate gas policy.

## Verification

`integration/pkg/accessors/evm/txm_error_handler_test.go` covers:

- Both rejection strings, including RPC suffixes.
- Immediate nonce reuse by the next transaction.
- One discard per accepted handler invocation and no discards for later attempts, unrelated errors, or nil errors.
- CCIP message IDs in discard logs.

## References

- Prior TXM recovery change: `2026-11-06_standalone_txm_v2_recovery.md`
- TXM v2 assessment: `docs/migration/txm-v2-assessment.md`
