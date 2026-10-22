# Executor coordinator lifecycle handling

## Executive Summary

- The executor coordinator's dispatch, shutdown, and retry behavior was tightened across `executor/executor_coordinator.go` and `executor/pkg/executor/cl_executor.go`.
- Messages affected by a transiently unhealthy destination reader are now retried instead of dropped at discovery.
- Consumers of `executor.Coordinator` and `executor.ChainlinkExecutor` see behavior changes only; no signatures changed and no migration is required.
- Adds one exported sentinel (`executor.ErrDestinationReaderUnhealthy`) and one metric reason constant (`monitoring.MessageTransitionReasonReaderUnhealthy`).

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `executor.Coordinator` dispatch/shutdown | behavior-changed | `NewCoordinator\(` | `executor/executor_coordinator.go:325` | [#coordinator-behavior](#coordinator-behavior) |
| `executor.ChainlinkExecutor.CheckValidMessage` | behavior-changed | `\.CheckValidMessage\(` | `executor/pkg/executor/cl_executor.go:170` | [#destination-reader-health-retries](#destination-reader-health-retries) |
| `executor.ChainlinkExecutor.HandleMessage` | behavior-changed | `\.HandleMessage\(` | `executor/pkg/executor/cl_executor.go:194` | [#destination-reader-health-retries](#destination-reader-health-retries) |
| `executor.ErrDestinationReaderUnhealthy` | added | `\bErrDestinationReaderUnhealthy\b` | `executor/types.go:18` | [#destination-reader-health-retries](#destination-reader-health-retries) |
| `monitoring.MessageTransitionReasonReaderUnhealthy` | added | `\bMessageTransitionReasonReaderUnhealthy\b` | `executor/pkg/monitoring/metrics.go:45` | [#destination-reader-health-retries](#destination-reader-health-retries) |

## Breaking Changes

*No breaking changes.*

## Coordinator behavior

- `runProcessingLoop` records a message as in-flight before handing it to a
  worker, so fast-terminal dispatches leave the in-flight map empty afterwards.
- On shutdown mid-dispatch, the processing loop re-queues undispatched messages
  back onto the delayed heap instead of discarding them, and logs the requeue at
  Info level.
- `runStorageStream` logs a closed component-errors channel once and stops
  selecting on it.
- `handleMessage` returns when the worker pool channel is closed.
- `dataNotReadyBackoff` falls back to the configured base retry interval when
  the exponential shift overflows and no cap is set (previously it returned 0);
  capped behavior is unchanged.

## Destination reader health retries

- `CheckValidMessage` now wraps destination-reader `CheckHealth` failures with
  `executor.ErrDestinationReaderUnhealthy` (message text unchanged;
  `errors.Is` matches). Missing reader/transmitter errors stay plain.
- `HandleMessage` returns `shouldRetry=true` when `CheckValidMessage` fails with
  an unhealthy destination reader; other validity failures remain non-retryable.
- `runStorageStream` no longer drops messages on this condition: it logs at Warn
  level and continues the normal scheduling path (leader-elector ready timestamp
  and retry delay, heap push). The discovery transition metric carries the new
  `reader_unhealthy` reason on this path.
