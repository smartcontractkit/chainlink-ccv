# Distributed message tracing across executor and verifier pipelines

## Executive Summary

- Add W3C-traceparent-based distributed tracing across the executor coordinator and verifier task pipeline, backed by a new `common/monitoring/tracing` package and a `Tracing()` method on `verifier.Monitoring` and `executor/pkg/monitoring.Monitoring`.
- Persist `traceparent` on `verifier_node_results` (Postgres) so trace context survives DB round-trips — **breaking DB migration**, column is `NOT NULL DEFAULT ''`.
- `executor.NewCoordinator` gains a required `executorID string` positional parameter — **breaking signature change** for all callers.
- Span/event/attribute names centralized as constants/funcs instead of string literals: `common/monitoring/tracing/keys.go` (shared attr keys), `executor/pkg/monitoring/tracing.go` (executor event names + `DiscoverySpanName`/`ProcessPayloadSpanName`), `verifier/pkg/monitoring/tracing.go` (verifier event names + `MessageDiscoverySpanName`/`MessageTaskSendSpanName`/`TaskVerifierAttemptSpanName`/`StorageWriterWriteSpanName`).
- Affects: `verifier/pkg/*` (interfaces, storage, taskverifier, sourcereader, storagewriter, commit/utils, monitoring), `executor/*` (coordinator, message_heap, pkg/monitoring, pkg/executor), `common/monitoring/tracing` (new).

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `executor.NewCoordinator` | signature-changed | `NewCoordinator\(` | `executor/executor_coordinator.go:49` | [#coordinator-executorid-param](#coordinator-executorid-param) |
| `verifier_node_results.traceparent` (Postgres column) | added / behavior-changed | `traceparent` | `verifier/migrations/postgres/00008_add_verifier_results_traceparent.sql` | [#traceparent-column](#traceparent-column) |
| `verifier.Monitoring.Tracing` / `executor/pkg/monitoring.Monitoring.Tracing` | added | `\.Tracing\(\)` | `verifier/pkg/vtypes/interfaces.go:51`, `executor/pkg/monitoring/interfaces.go:20` | [#tracing-interface](#tracing-interface) |
| `verifier.VerificationTask.TraceParent` / `.TraceContext` | added | `\.TraceParent\b\|\.TraceContext\b` | `verifier/pkg/vtypes/types.go:21-22` | [#tracing-interface](#tracing-interface) |
| `protocol.VerifierNodeResult.TraceParent` / `.TraceContext` | added | `VerifierNodeResult\{` | `protocol/message_types.go` | [#traceparent-column](#traceparent-column) |
| `message_heap.MessageWithTimestamps.TraceContext` / `.DiscoveryContext` | added | `DiscoveryContext` | `executor/pkg/message_heap/message_heap.go:21-29` | [#tracing-interface](#tracing-interface) |
| `common/monitoring/tracing` (package) | added | `common/monitoring/tracing` | `common/monitoring/tracing/tracing.go` | [#tracing-interface](#tracing-interface) |
| `executor/pkg/monitoring.DiscoverySpanName` / `.ProcessPayloadSpanName` | added | `DiscoverySpanName\|ProcessPayloadSpanName` | `executor/pkg/monitoring/tracing.go` | [#span-lifecycle](#span-lifecycle) |
| `verifier/pkg/monitoring.MessageDiscoverySpanName` / `.MessageTaskSendSpanName` | added | `MessageDiscoverySpanName\|MessageTaskSendSpanName` | `verifier/pkg/monitoring/tracing.go` | [#span-lifecycle](#span-lifecycle) |

## Breaking Changes

### coordinator-executorid-param

- **What changed:** `executor.NewCoordinator` signature.
- **Before:** `NewCoordinator(lggr, executor, messageSubscriber, leaderElector, monitoring, expiryDuration, timeProvider, workerCount, dataNotReadyRetryInterval)`
- **After:** `NewCoordinator(lggr, executorID string, executor, messageSubscriber, leaderElector, monitoring, expiryDuration, timeProvider, workerCount, dataNotReadyRetryInterval)`
- **Why:** `executorID` names the per-message discovery span (`DiscoverySpanName(executorID)` → `"executor.message.discovery@" + executorID`), attributing traces to the executor instance that discovered the message.
- **Who is affected:** Any code constructing an `executor.Coordinator` directly (e.g. `cmd/executor/service.go`, integration/test harnesses).

### traceparent-column

- **What changed:** `verifier_node_results` Postgres table gains `traceparent TEXT NOT NULL DEFAULT ''`; `protocol.VerifierNodeResult` and `verifier.VerificationTask` gain `TraceParent`/`TraceContext` fields; `storage/postgres.go` upsert now writes/reads `traceparent` (`ON CONFLICT ... traceparent = EXCLUDED.traceparent`).
- **Before:** No trace propagation persisted; column did not exist.
- **After:** Every verifier result write includes `traceparent` (W3C traceparent string derived from the OTel span, or `''` if no trace context). Existing rows backfill to `''` on migration.
- **Why:** Enables end-to-end tracing of a message from discovery through execution/verification across process and storage boundaries.
- **Who is affected:** Any consumer reading `verifier_node_results` directly (raw SQL, BI/reporting); deployments must apply migration `00008` before running code from this change.

## Migration Guide

1. Run migration `00008_add_verifier_results_traceparent.sql` (adds `traceparent TEXT NOT NULL DEFAULT ''`; down-migration does `DROP COLUMN traceparent`).
2. Update all `executor.NewCoordinator(...)` call sites to pass an `executorID string` as the second argument.
3. If you have a custom `verifier.Monitoring` or `executor.Monitoring` implementation, add a `Tracing() tracing.Tracing` method (use `common/monitoring/tracing.NewTracing(beholder.GetTracer())` for the standard beholder-backed implementation, or a no-op for tests/fakes).

```go
// Before
coord, err := executor.NewCoordinator(lggr, exec, sub, elector, mon, expiry, tp, workers, retryInterval)
```

```go
// After
coord, err := executor.NewCoordinator(lggr, executorID, exec, sub, elector, mon, expiry, tp, workers, retryInterval)
```

## New Features / Additions

- **Distributed message tracing** — `common/monitoring/tracing.Tracing.StartMessageSpan(ctx, name, messageID, attrs...)` derives a deterministic OTel `TraceID` from the message ID when no real parent span exists, so all spans for a given message land in one trace even across process/queue boundaries. `SpanFromContext`/`StartMessageSpan` tolerate a nil `ctx` (returns a no-op span / falls back to `context.Background()`), since `TraceContext` fields on tasks/messages may legitimately be unset. See `common/monitoring/tracing/tracing.go`.
- **Span lifecycle (span-lifecycle)** — discovery spans (executor coordinator, verifier sourcereader) end immediately once the message/task is formed rather than staying open across the multi-tick delay/retry/pending lifecycle; each subsequent operation opens its own short-lived span parented off the (ended) discovery span's context, so the trace hierarchy stays intact without holding spans open for minutes/hours:
  - Executor: `DiscoverySpanName(executorID)` span ends right after scheduling; each dequeue opens a fresh `ProcessPayloadSpanName(executorID)` attempt span (`DiscoveryContext` carried on `message_heap.MessageWithTimestamps`).
  - Verifier sourcereader: `MessageDiscoverySpanName(verifierID)` span ends right after `addToPendingQueueHandleReorg`; each send-loop tick opens a fresh `MessageTaskSendSpanName(verifierID)` span per pending task, which carries curse/disablement/readiness events (`cursed_dropped`, `disabled_dropped`, `ready_for_verification`, `not_ready_for_verification`) and, once ready, is threaded through as the task's `TraceContext`/`TraceParent` so publish (`task_published`) ends the same span.
  - Verifier taskverifier/storagewriter: per-attempt (`TaskVerifierAttemptSpanName`) and per-write (`StorageWriterWriteSpanName`) spans parented off the propagated `traceparent`, ended via `defer` with an `IsRecording()`-guarded safety net.
  - Event/attribute names for all of the above are centralized in `executor/pkg/monitoring/tracing.go` and `verifier/pkg/monitoring/tracing.go` (event constants) plus `common/monitoring/tracing/keys.go` (shared attribute keys, e.g. `RetryableKey`, `LatestBlockNumberKey`/`LatestSafeBlockNumberKey`/`LatestFinalizedBlockNumberKey`) — no ad-hoc string literals at call sites.

## Compatibility & Requirements

- Requires migration `00008_add_verifier_results_traceparent.sql` applied before deploying verifier builds from this changeset.
- Depends on `go.opentelemetry.io/otel` (`trace`, `attribute`, `propagation`) and `chainlink-common/pkg/beholder` for the default tracer.
