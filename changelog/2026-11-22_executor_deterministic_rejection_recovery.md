# Executor deterministic rejection recovery

## Executive Summary

- Standalone TXM v2 now handles deterministic first-broadcast gas rejections instead of waiting for AutoPurge. A rejected newest nonce is immediately reused; an older nonce becomes purgeable for empty-transaction backfill.
- `PendingNonceAt` guards against discarding a transmission another node accepted, and purge/nonce-gap transactions are excluded.
- Geth's `intrinsic gas too low` and `insufficient gas for floor data gas cost`, Besu's `Intrinsic gas exceeds gas limit`, and Hedera's intrinsic-gas rejection are recognized case-insensitively, including backend-specific suffixes.
- `executor_txm_discarded_transactions_total{chainID}` and the standard broadcast-lifecycle failure counter record handled rejections. Logs include CCIP message IDs supplied by the transmitter.
- AutoPurge remains an optional, separately configured backstop for later attempts, mempool-stuck transactions, and unmatched deterministic failures.
- No transmitter gas estimation or additional gas top-up is introduced. Testnet retains its separate `LimitMultiplier = 2` stopgap while the backlog drains; no mainnet multiplier is prescribed.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evm.deterministicTxErrorHandler.HandleError` | added | `deterministicTxErrorHandler` | `integration/pkg/accessors/evm/txm_error_handler.go` | [#deterministic-rejection-handling](#deterministic-rejection-handling) |
| `evm.NewCCVTxmMetrics` | added | `NewCCVTxmMetrics\(` | `integration/pkg/accessors/evm/txm_metrics.go` | [#discard-observability](#discard-observability) |
| `evm.newTxmV2` | behavior-changed | `newTxmV2\(` | `integration/pkg/accessors/evm/txm.go` | [#deterministic-rejection-handling](#deterministic-rejection-handling) |

## Breaking Changes

*No breaking changes.* The change is internal to standalone TXM v2 construction and does not alter the executor or transmitter APIs.

## Deterministic rejection handling

`newTxmV2` installs `deterministicTxErrorHandler` instead of a nil error handler. It handles only non-purgeable transactions on their first broadcast and first checks `PendingNonceAt`: an increased pending nonce leaves the transaction under normal TXM handling.

When the rejected transaction holds the latest assigned nonce, the handler deletes it from the in-memory store and rewinds exactly one nonce. The next transaction immediately reuses that nonce. Such deleted transactions no longer appear in TXM status or idempotency-key lookups; the store does not retain a queryable fatal record.

When later nonces were already assigned, rewinding would collide with in-flight work. The handler instead marks the older transaction purgeable, and the next backfill tick replaces its contents with an empty transaction at the same nonce even when AutoPurge is disabled. Existing purge and nonce-gap transactions, later attempts, unrelated RPC errors, and failed pending-nonce reads are left to normal TXM handling.

AutoPurge is off by default and is not a universal backstop. Enable it with `Threshold` and `MinAttempts` where coverage is wanted for later attempts, mempool-stuck transactions, and other deterministic failures such as the per-transaction gas cap.

## Discard observability

`NewCCVTxmMetrics` wraps the standard TXM metrics without changing the upstream interface. Each handled rejection increments `executor_txm_discarded_transactions_total` with a `chainID` label and `txm_transaction_lifecycle_failure_total` with `stage="broadcast"`. The log includes `txID`, `nonce`, `nonceRewound`, `messageIDs`, and the RPC error. The transmitter populates `MessageIDs` from each CCIP report. Metric initialization failure degrades the new counter to log-only behavior without preventing recovery.

The integration TXM package is registered in `tools/metricsgolden/registry`; the golden file includes the discard counter and the standard TXM instruments.

## Recovery

For testnet recovery, retain the separate `LimitMultiplier = 2` stopgap with `EstimateLimit = false`, enable AutoPurge with positive `Threshold` and `MinAttempts`, and temporarily expand `startup_lookback_window` to eight hours for a canary restart followed by controlled fleet waves. Restore the one-hour lookback after the backlog drains. Verify execution through the destination OffRamp rather than indexer verification status.

The durable pricing fix is the complete Solana Glamsterdam migration, including router, fee-quoter, verifier, and token-pool gas fields. Follow up in the lane tooling to replace its pre-fork 20-gas-per-byte default or enforce destination fork minimums for newly built lanes. Messages older than the eight-hour retry window require the reviewed manual-execution path.

Do not carry the multiplier into mainnet configuration before product decides the appropriate gas policy.

## Verification

`integration/pkg/accessors/evm/txm_error_handler_test.go` covers:

- Geth, Besu, and Hedera rejection strings, including case differences and RPC suffixes.
- Immediate reuse of a nonzero nonce through the real TXM broadcast path.
- Older-nonce and missing-nonce-getter purging without a rewind, and preservation of later in-flight nonces.
- No discard for accepted transmissions, failed nonce reads, existing purge transactions, later attempts, unrelated errors, nil errors, or nil nonces.
- Discard and lifecycle metrics plus CCIP message IDs in logs.

## References

- Prior TXM recovery change: `2026-11-06_standalone_txm_v2_recovery.md`
- TXM v2 assessment: `docs/migration/txm-v2-assessment.md`
