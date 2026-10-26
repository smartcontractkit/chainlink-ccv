# Source reader disabled on critical invariant violation

## Executive Summary

- Source-reader invariant violations are now two-tiered. Critical violations (the checks that were `Fatalw` before this stack: onRamp address, sender, message ID, and destination chain selector mismatches, plus the new source chain selector check) permanently disable the reader for that chain: `FetchMessageSentEvents` fails with the new sentinel `chainaccess.ErrSourceReaderDisabled` on every later call.
- Non-critical violations (the checks that were `Errorw`: insufficient topics/receipts, unpack/decode failure, zero or mismatched `ccvAndExecutorHash`) are again plain error logs that skip only the offending message; the reader keeps serving the chain. Both tiers still increment the critical-invariant metric.
- The verifier's source-reader service treats `ErrSourceReaderDisabled` like a finality violation: it flushes pending and sent tasks, latches the chain disabled, persists `ChainStatusInfo{Disabled: true}` (durable across restarts until an operator resets the reader), and reports NotReady via the new `invariantBlocked` flag.
- This preserves the safety of the removed `Fatalw` calls (no message from an untrusted chain is verified) without killing the whole verifier process, while restoring error-level handling for violations that occur in practice without chain corruption.
- Adds one exported sentinel and two metric label constants; no signatures changed.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `chainaccess.ErrSourceReaderDisabled` | added | `ErrSourceReaderDisabled` | `pkg/chainaccess/interfaces.go:80` | [#reader-latch](#reader-latch) |
| `evm.sourceReaderCore.onCriticalInvariant` | behavior-changed | `onCriticalInvariant\(` | `integration/pkg/accessors/evm/evm_source_reader.go:206` | [#reader-latch](#reader-latch) |
| `evm.sourceReaderCore.onInvariantViolation` | added | `onInvariantViolation\(` | `integration/pkg/accessors/evm/evm_source_reader.go:217` | [#reader-latch](#reader-latch) |
| `chainaccess.SourceReader.FetchMessageSentEvents` (EVM impls) | behavior-changed | `FetchMessageSentEvents\(` | `integration/pkg/accessors/evm/evm_source_reader.go:301`, `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:262` | [#reader-latch](#reader-latch) |
| `sourcereader.Service.handleSourceInvariantViolation` | added | `handleSourceInvariantViolation` | `verifier/pkg/sourcereader/service.go:1241` | [#verifier-chain-disable](#verifier-chain-disable) |
| `sourcereader.Service.Ready` | behavior-changed | `invariantBlocked` | `verifier/pkg/sourcereader/service.go:323` | [#verifier-chain-disable](#verifier-chain-disable) |
| `monitoring.MessageTransitionOutcomeSourceDisabled` / `MessageTransitionReasonSourceInvariantViolation` | added | `source_invariant_violation` | `verifier/pkg/monitoring/metrics.go:33` | [#verifier-chain-disable](#verifier-chain-disable) |

## Breaking Changes

*No breaking changes.* `ErrSourceReaderDisabled` is additive; consumers that do not match it see an ordinary read error.

## Reader latch

- `sourceReaderCore` gains a `disabled *atomic.Bool` latch (a pointer because both readers embed the core by value and must share one latch), allocated in `newSourceReaderCore` (`evm_source_reader.go:169`).
- `onCriticalInvariant` (`evm_source_reader.go:206`) stores the latch, fires the metric callback, and logs `Criticalw`. It is used by exactly the violations that were `Fatalw` before this stack (onRampAddress, sender, messageID, destChainSelector mismatches) plus the new sourceChainSelector check added in this PR, which is the same configured-value class.
- The new `onInvariantViolation` (`evm_source_reader.go:217`) fires the metric callback and logs `Errorw` without disabling. It covers the violations that were `Errorw` before: insufficient topics, unpack failure, insufficient receipts, decode failure, zero `ccvAndExecutorHash`, and `ccvAndExecutorHash` validation failure (the last one now also increments the metric, which it did not before).
- Within the batch being parsed, behavior is unchanged: the offending log is skipped, remaining logs are still validated and returned. The latch applies to subsequent `FetchMessageSentEvents` calls on both the RPC reader (`evm_source_reader.go:301`) and the log poller reader (`evm_logpoller_source_reader.go:262`), which return `fmt.Errorf("%w: chain selector %d", chainaccess.ErrSourceReaderDisabled, ...)`.

## Verifier chain disable

- `processEventCycle` (`verifier/pkg/sourcereader/service.go:479`) detects `errors.Is(err, chainaccess.ErrSourceReaderDisabled)` from `loadEvents` and calls the new `handleSourceInvariantViolation` instead of retrying the poll.
- `handleSourceInvariantViolation` (`service.go:1244`) mirrors `handleFinalityViolation`: it latches `disabled` plus the new `invariantBlocked` flag, flushes `pendingTasks`/`sentTasks` with transition outcome `source_disabled` and reason `source_invariant_violation` (span event `disabled_dropped`), sets source-reader state `disabled`, and persists `ChainStatusInfo{Disabled: true, FinalizedBlockHeight: 0}` so the chain stays down across restarts until an operator resets the reader. The flush and persist bodies are now shared with the finality path via `flushTasksLocked` and `persistDisabledLocked`.
- `Ready()` (`service.go:323`) reports `source invariant violation` while `invariantBlocked` is set, so `/health` goes NotReady for the chain — unlike an operator-disabled chain, which is intentionally idle and stays Ready.

## References

- Stacked on: `changelog/2026-10-20_admin_console_request_handling.md`
- PR review: disable the per-chain source reader on critical invariant violations instead of the removed `Fatalw`; keep error-level handling for the violations that were never fatal.
