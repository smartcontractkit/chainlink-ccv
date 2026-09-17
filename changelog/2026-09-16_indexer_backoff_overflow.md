# Indexer scheduler backoff overflow and rate limiter retry fix

## Executive Summary

- This change fixes a signed integer overflow in the indexer scheduler backoff function that caused stuck messages to retry at the ticker interval (~50 ms) instead of the configured backoff delay (up to 30 s). It also includes a follow-up fix to the resilient reader retry policy added in #1364 so that rate-limited requests abort cleanly instead of retrying and cycling the circuit breaker.
- The scheduler backoff function shifted `BaseDelay` left by the attempt count without an overflow guard; at high attempt counts the result became zero, so the scheduler dispatched the task on every tick with no delay. Separately, the retry policy from #1364 did not exclude `ratelimiter.ErrExceeded` from retry or the circuit breaker, so a rate-limited request would retry in a loop and open the breaker.
- Affects `indexer/pkg/worker` (scheduler backoff) and `indexer/pkg/readers` (resilient reader policy stack).
- No breaking changes. No configuration changes. No migration steps.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `worker.Scheduler.backoff` | behavior-changed | `func \(s \*Scheduler\) backoff` | `indexer/pkg/worker/scheduler.go:127` | [#scheduler-backoff-overflow](#scheduler-backoff-overflow) |
| `readers.createPolicies` | behavior-changed | `func createPolicies\[T any\]` | `indexer/pkg/readers/resilient_reader.go:105` | [#rate-limiter-and-circuit-breaker](#rate-limiter-and-circuit-breaker) |

## Breaking Changes

No breaking changes.

## Migration Guide

No migration steps. The fix is internal and does not change any public API, configuration key, or wire format.

## Scheduler backoff overflow

### Root cause

`Scheduler.backoff` (`indexer/pkg/worker/scheduler.go:127`) computed the retry delay as `BaseDelay << (attempt - 1)` using signed `int` arithmetic. For a 64-bit `int`, the shift overflows at high attempt counts:

- At shift 61, a bit lands on the sign bit. The result becomes negative. The guard `d < 0` caught this and reset the delay to `BaseDelay`.
- At shift 62 and above, all bits shift past the 64-bit boundary. The result becomes **zero**. The guard `d < 0` did not catch zero, so the function returned a delay of 0 ms.

With a delay of 0 ms, the scheduler set `runAt = now`. The heap function `PopAllReady()` (`indexer/pkg/worker/heap.go:65`) dispatched the task on the next tick. With `TickerInterval = 50` ms, the task retried every ~50 ms instead of every 30 s.

Production logs confirmed the bug: message `0xa9e0fc65...` at attempt 191,962 retried 53 ms after attempt 191,961. The configured `MaxDelay` was 30,000 ms (30 s).

### Fix

The overflow guard changed from `d < 0` to `d <= 0` and is gated on `BaseDelay > 0` so that the legitimate `BaseDelay = 0` fast-path (immediate dispatch, used in tests) is not affected. When overflow is detected, the delay resets to `MaxDelay` instead of `BaseDelay`, so the scheduler uses the maximum retry spacing for a message that has already been retrying for a long time. The `attempt < 0` guard was also changed to `attempt < 1` to prevent a negative shift (`BaseDelay << -1`), which is undefined behavior in Go.

The overflow warning was also corrected: it now reports the actual non-positive delay value, the messageID, and the attempt count, instead of claiming the delay `overflowed to zero` in every case.

## Rate limiter and circuit breaker

### Root cause

The retry policy added in #1364 built the retry policy and circuit breaker without special handling for `ratelimiter.ErrExceeded`. When the rate limiter rejected a request after its 1 s wait budget, two things happened:

1. The retry policy retried the request, because `ErrExceeded` was not in the `AbortOnErrors` list. Each retry hit the rate limiter again, so the request retried in a loop until `MaxRetries` was exhausted.
2. The circuit breaker counted `ErrExceeded` as a failure, because `cbHandleIf` returned `true` for any non-nil error. After `FailureThreshold` consecutive rejections, the breaker opened and subsequent requests failed immediately with `circuitbreaker.ErrOpen`.

The combined effect: a reader that exceeded its rate limit would retry rapidly, open the circuit breaker, and then fail all requests for `CircuitBreakerDelay` (default 3 s). When the breaker closed, the cycle repeated. This policy is not yet deployed to staging, so this is a follow-up fix before rollout.

### Fix

Two changes in `createPolicies`:

1. `ratelimiter.ErrExceeded` was added to the retry policy `AbortOnErrors` list. A rate-limited request now aborts immediately instead of retrying. The caller receives `ErrExceeded` and the scheduler applies backoff before the next attempt.

2. The circuit breaker `HandleIf` function now checks `errors.Is(err, ratelimiter.ErrExceeded)` and returns `false`, so rate limiter rejections do not count as downstream failures and do not open the breaker.

## New Features / Additions

No new features.

## Compatibility & Requirements

- **Rollout:** no feature flags. No configuration change. A binary swap applies the fix.
- **Rollback:** a binary swap reverts the fix. No schema, persistence, or wire-format change.
- **Dependencies:** none added.
- **Observability note:** after rollout, the delay resets to `MaxDelay` instead of `BaseDelay`, so a stuck message retries at the `MaxDelay` cadence (30 s in production) instead of every tick. The `Invariant Check triggered in Scheduler` warning is emitted once per retry while a message is in the overflow range — bounded by the `MaxDelay` cadence, roughly 2,880 lines per day per stuck message — and each line includes the messageID, attempt count, non-positive delay value, and `MaxDelay` fallback, so retries can be traced per message. Circuit breaker `opened` events caused by rate limiter rejections should not occur once the retry policy from #1364 deploys with this fix.

## References

- Branch: `jh/indexer-backoff-overflow`
- Prior changelog entry: `2026-09-13_resilient_reader_config.md` (added the retry policy and resilience config that this fix corrects)
- Production evidence: message `0xa9e0fc65...` retried at 53 ms intervals at attempt 191,962 with `BaseDelay=100`, `MaxDelay=30000`, `TickerInterval=50`
