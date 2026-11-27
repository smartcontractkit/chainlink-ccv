# Execution attempt poller survives ExecutionStateChanged log floods

## Executive Summary

- `EvmExecutionAttemptPoller` now splits RPC ranges that fail, advances its cursor per completed sub-range, and memoizes per-transaction lookups.
- Affects `integration/pkg/destinationreader` only; no exported symbols or config change.
- Behavior change only: the poller keeps making progress under load, and `Ready()` tracks progress rather than full-poll success.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `destinationreader.EvmExecutionAttemptPoller.pollForEvents` | behavior-changed | `\.pollForEvents\(` | `integration/pkg/destinationreader/evm_execution_attempt_poller.go:706` | [#polling-and-readiness](#polling-and-readiness) |
| `destinationreader.EvmExecutionAttemptPoller.Ready` | behavior-changed | `executionAttemptPoller\.Ready\(` | `integration/pkg/destinationreader/evm_execution_attempt_poller.go:127` | [#polling-and-readiness](#polling-and-readiness) |
| `destinationreader.EvmExecutionAttemptPoller.scanRange` | added | `\.scanRange\(` | `integration/pkg/destinationreader/evm_execution_attempt_poller.go:763` | [#polling-and-readiness](#polling-and-readiness) |
| `destinationreader.EvmExecutionAttemptPoller.scanBlockDirect` | added | `\.scanBlockDirect\(` | `integration/pkg/destinationreader/evm_execution_attempt_poller.go:824` | [#polling-and-readiness](#polling-and-readiness) |
| `destinationreader.EvmExecutionAttemptPoller.resolveTx` | added | `\.resolveTx\(` | `integration/pkg/destinationreader/evm_execution_attempt_poller.go:1022` | [#transaction-memo](#transaction-memo) |

## Breaking Changes

*No breaking changes.*

## Polling and readiness

- **Range splitting:** `scanRange` bisects a range the RPC rejects. The cursor (`lastPolledBlock`) and `lastSuccessfulPoll` advance after each completed sub-range.
- **Single-block fallback:** if one block alone fails the log query, `scanBlockDirect` reads that block's transactions, keeps only those sent directly to the OffRamp, and parses their receipts. Each receipt must match the fetched block's hash and number, and the block is rechecked as canonical before events are processed; a mismatch (reorg) or any other failure holds the cursor at that block (never skipped) and `pollForEvents` returns an error.
- **Readiness:** `Ready()` logic is unchanged, but `lastSuccessfulPoll` now refreshes whenever a range completes, so a poller that is advancing is not reported stale.
- **Logging:** failures while processing a batch are logged once per batch with a count, not once per log.

## Transaction memo

`resolveTx` fetches and decodes each transaction once per hash. Deterministic rejections (destination is not the OffRamp, call data does not decode) are cached, so a multi-log transaction or a retried range costs one `TransactionByHash`. Transient RPC errors are not cached. The cache holds 10,000 entries with the attempt-cache TTL.

## Compatibility & Requirements

- **Chain RPC:** the single-block fallback needs `BlockByNumber` and `TransactionReceipt` on the destination chain client.
- **Known limit:** an RPC that silently truncates `eth_getLogs` results without returning an error is not detected.
