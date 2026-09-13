# Configurable resilience policies for the indexer readers

## Executive Summary

- The indexer's `ResilientReader` policies (rate limit, bulkhead, circuit breaker, timeout) are now configurable through a `[Resilience]` TOML section, and a retry policy with exponential backoff was added to the policy stack.
- Before, all policy values were hardcoded in `readers.DefaultResilienceConfig()`, a single failed request surfaced to the caller immediately, and a `CircuitBreakerTimeout` field existed but was never read by any policy.
- Affects `indexer/pkg/config`, `indexer/pkg/readers`, and the reader construction call sites in `indexer/cmd/main.go` and `indexer/cmd/replay/main.go`.
- Breaking for Go consumers of the readers package: `NewAggregatorReader` gained a trailing parameter, `RestReaderConfig` gained a required-in-practice `Resilience` field, and `ResilienceConfig.CircuitBreakerTimeout` was removed. TOML users are unaffected: the section is optional and every key defaults.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `readers.ResilienceConfig.CircuitBreakerTimeout` | removed | `CircuitBreakerTimeout` | — | [#circuitbreakertimeout-removed](#circuitbreakertimeout-removed) |
| `readers.NewAggregatorReader` | signature-changed | `NewAggregatorReader\(` | `indexer/pkg/readers/aggregator_reader.go:14` | [#reader-constructors](#reader-constructors) |
| `readers.NewRestReader` | behavior-changed | `NewRestReader\(` | `indexer/pkg/readers/rest_reader.go:53` | [#reader-constructors](#reader-constructors) |
| `readers.ResilienceConfig` | behavior-changed | `readers\.ResilienceConfig\b` | `indexer/pkg/readers/resilient_reader.go:27` | [#readersresilienceconfig](#readersresilienceconfig) |
| `readers.DefaultResilienceConfig` | behavior-changed | `readers\.DefaultResilienceConfig\(` | `indexer/pkg/readers/resilient_reader.go:47` | [#readersresilienceconfig](#readersresilienceconfig) |
| `readers.ResilientReader` | behavior-changed | `NewResilientReader\(` | `indexer/pkg/readers/resilient_reader.go:87` | [#policy-stack](#policy-stack) |
| `readers.NewResilienceConfig` | added | `NewResilienceConfig\(` | `indexer/pkg/readers/resilient_reader.go:54` | [#readersresilienceconfig](#readersresilienceconfig) |
| `config.Config.Resilience` | added | `\.Resilience\b` | `indexer/pkg/config/config.go:57` | [#toml-resilience-section](#toml-resilience-section) |
| `config.ResilienceConfig` | added | `config\.ResilienceConfig\b` | `indexer/pkg/config/config.go:62` | [#toml-resilience-section](#toml-resilience-section) |
| `config.DefaultResilienceConfig` | added | `config\.DefaultResilienceConfig\(` | `indexer/pkg/config/config.go:93` | [#toml-resilience-section](#toml-resilience-section) |
| `config.ResilienceConfig.Validate` | added | `Resilience\.Validate\(` | `indexer/pkg/config/config.go:423` | [#toml-resilience-section](#toml-resilience-section) |

## Breaking Changes

### CircuitBreakerTimeout removed

- **What changed:** the field was deleted from `readers.ResilienceConfig`.
- **Before:** the field existed (default `1s`) but `createPolicies` never read it. It configured nothing.
- **After:** gone. The failsafe-go v0.9 circuit breaker has no timeout parameter at all — its only timing knob is `WithDelay`, which is wired to `CircuitBreakerDelay`.
- **Why:** carrying a dead knob invites operators to tune a value that cannot take effect.
- **Who is affected:** only hand-written `readers.ResilienceConfig` struct literals; compile error on the field name.

### NewAggregatorReader signature

- **What changed:** trailing parameter `resiConfig ResilienceConfig` added.
- **Before:** `NewAggregatorReader(address, lggr, since, hmacConfig, insecure, maxRecvMsgSizeBytes, m)` — policies were hardcoded to `readers.DefaultResilienceConfig()`.
- **After:** `NewAggregatorReader(address, lggr, since, hmacConfig, insecure, maxRecvMsgSizeBytes, m, resiConfig)`.
- **Why:** policy values must come from the indexer's TOML config.
- **Who is affected:** every caller; compile error.

### NewRestReader resilience is caller-supplied

- **What changed:** `RestReaderConfig` gained a `Resilience ResilienceConfig` field and `NewRestReader` no longer substitutes defaults.
- **Before:** `NewRestReader` wrapped the HTTP reader with `readers.DefaultResilienceConfig()` implicitly.
- **After:** the supplied `Resilience` field is used as-is. The reader does **not** resolve zero values; a zero struct yields zero thresholds (e.g. a circuit breaker that opens after 0 failures). Pass `readers.NewResilienceConfig(cfg.Resilience)` from validated config, or `readers.DefaultResilienceConfig()`.
- **Who is affected:** every `NewRestReader` caller; compiles silently, misbehaves at runtime if the field is left zero.

### readers.ResilienceConfig field set changed

- **What changed:** `CircuitBreakerTimeout` removed; `MaxRetries int`, `RetryDelay time.Duration`, `RetryMaxDelay time.Duration` added; the single per-API `errorHandler` was split into a retry handler and a circuit-breaker handler.
- **Before:** no retry fields; no retry policy existed, so a struct literal needed only the six threshold/timing fields.
- **After:** a hand-written literal that leaves `MaxRetries` zero gets **no retries** (failsafe treats 0 as "don't retry"), while validated TOML config maps 0 to the default of 3. Set the retry fields or start from `readers.DefaultResilienceConfig()`.
- **Who is affected:** hand-written literals and any caller passing the old single `errorHandler` argument shape to `createPolicies` (unexported, so in-package only).

## Migration Guide

1. Update `NewAggregatorReader` calls to pass resilience config:

```go
// Before
reader, err := readers.NewAggregatorReader(addr, lggr, since, hmacCfg, insecure, maxBytes, metrics)

// After — from validated TOML config
reader, err := readers.NewAggregatorReader(addr, lggr, since, hmacCfg, insecure, maxBytes, metrics,
    readers.NewResilienceConfig(cfg.Resilience))
// After — previous hardcoded behavior (plus the new retry defaults)
reader, err := readers.NewAggregatorReader(addr, lggr, since, hmacCfg, insecure, maxBytes, metrics,
    readers.DefaultResilienceConfig())
```

2. Set the `Resilience` field in every `RestReaderConfig`:

```go
// Before
r := readers.NewRestReader(readers.RestReaderConfig{BaseURL: u, Logger: lggr, ...})

// After
r := readers.NewRestReader(readers.RestReaderConfig{BaseURL: u, Logger: lggr, ...,
    Resilience: readers.NewResilienceConfig(cfg.Resilience)})
```

3. Delete `CircuitBreakerTimeout` from any `readers.ResilienceConfig` literal. Nothing replaces it; `CircuitBreakerDelay` was and remains the only circuit-breaker timing control.
4. TOML deployments need no change. A missing `[Resilience]` section is valid: `Config.Validate` replaces every zero/negative value with its default before the readers see the config.

## readers.ResilienceConfig

Two config types now exist and must not be confused:

- `config.ResilienceConfig` (`indexer/pkg/config`) — TOML-facing, field-for-field identical to the `[Resilience]` section, durations as `common.Duration`. Its `Validate` is **mutating**: it writes resolved defaults back into the struct.
- `readers.ResilienceConfig` (`indexer/pkg/readers`) — adds the four error-handler function fields and drops TOML tags. `readers.NewResilienceConfig(config.ResilienceConfig)` is a pure field-for-field mapping and expects **already-validated** input; it does not resolve zeros.
- `readers.DefaultResilienceConfig()` now delegates to `config.DefaultResilienceConfig()` instead of hardcoding values, so the two cannot drift. Its 25+ call sites in discovery tests pick up the new retry defaults automatically.

## Policy stack

`ResilientReader` behavior changed in four ways, all inside `createPolicies` (`indexer/pkg/readers/resilient_reader.go:104`):

1. **A retry policy was added** and composed outermost: `failsafe.With(rp, cb, rl, bh, to)` orders first-outermost, so the effective stack is `RetryPolicy(CircuitBreaker(RateLimiter(Bulkhead(Timeout(fn))))))`. Every failed attempt is retried up to `MaxRetries` with exponential backoff (factor 2) between `RetryDelay` and `RetryMaxDelay`; the last failure is returned (`ReturnLastFailure`). Retries abort on `context.Canceled`, `context.DeadlineExceeded` and `circuitbreaker.ErrOpen` — so an open breaker stops the retry loop rather than feeding it.
2. **The timeout is per-attempt.** `RequestTimeout` (innermost policy) bounds each attempt, not the whole retry sequence. With defaults, a hanging endpoint surfaces after at most ~47 s (4 attempts × 10 s + 1 s + 2 s + 4 s backoff), against ~10 s before. Budget-sensitive callers should lower `RequestTimeout` or `MaxRetries` accordingly.
3. **The rate limiter waits up to 1 s for a permit** (`NewBurstyBuilder(...).WithMaxWaitTime(time.Second)`) instead of failing an over-budget call immediately. Combined with the retry policy, bursts now queue briefly rather than surfacing as errors.
4. **Execution honors the caller context** (`executor.WithContext(ctx)`); before, the failsafe executor ran without it, so caller cancellation could not abort in-flight policy logic.

Circuit breaker wiring is unchanged: `FailureThreshold`/`SuccessThreshold`/`CircuitBreakerDelay`, with open/half-open/close logs per API name. The `execute` error wrapping is unchanged (`circuit breaker is open...` / `failed to fetch data: %w`).

## TOML Resilience section

`[Resilience]` under the indexer config, parsed into `config.Config.Resilience` and validated by `Config.Validate` (`indexer/pkg/config/config.go:394`, error prefix `resilience config validation failed`). Every key is optional; zero or negative values are replaced with defaults; positive user values are kept even when below the default:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `MaxRequestsPerSecond` | uint | 5 | Bursty rate-limit permits per second, per reader |
| `MaxConcurrentRequests` | uint | 5 | Bulkhead capacity, per reader |
| `FailureThreshold` | uint32 | 5 | Consecutive failures that open the circuit breaker |
| `SuccessThreshold` | uint32 | 3 | Successes in half-open that close it |
| `CircuitBreakerDelay` | duration | `3s` | Time the breaker stays open before half-open |
| `RequestTimeout` | duration | `10s` | Per-attempt timeout |
| `MaxRetries` | int | 3 | Retry attempts per request (0 → default, not "no retries") |
| `RetryDelay` | duration | `1s` | Initial backoff delay |
| `RetryMaxDelay` | duration | `10s` | Backoff ceiling; must be ≥ `RetryDelay` (cross-field check, the only non-defaulting validation) |

## New Features / Additions

- **Retry with backoff for `ReadCCVData` and `GetVerifications`** — transient downstream errors no longer surface on first failure. See `indexer/pkg/readers/resilient_reader.go:110`.
- **Per-API error-handler split** — `RetryPolicyErrorHandler` / `CircuitBreakerErrorHandler` (and their `Discovery*` twins) allow different retryability and breaker-trip predicates per API.

## Compatibility & Requirements

- **Rollout:** no feature flags. The `[Resilience]` section is optional; absent or partial config behaves as before plus the new retry defaults.
- **Rollback:** a binary swap. No schema, persistence, or wire-format change.
- **Dependencies:** none added; `failsafe-go` was already in use.
- **Observability note:** after rollout, reader error logs should decrease while error latency can grow (see the ~47 s worst case above); `circuit breaker opened` / `retrying request` warnings are the new signal to alert on.

## References

- Branch: `jh/resilient-reader-config`
