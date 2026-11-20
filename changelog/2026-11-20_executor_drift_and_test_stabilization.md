# Executor drift detection and test stabilization

## Executive Summary

- Executor state reconstruction now rejects jobs whose `SourceExecutorAddresses` maps disagree instead of silently combining divergent source-chain configuration.
- Source-reader readiness clocks now retain nanosecond precision, preventing short staleness thresholds from expiring early at whole-second boundaries.
- Testify `Eventually` calls use the shared test timeout helper, and a new analyzer rejects constant timeouts below ten seconds.
- Known timing-sensitive tests now wait for observable conditions or compare timestamps at EVM header precision; no public API or configuration migration is required.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `changesets.executorConfigDrift` | behavior-changed | `SourceExecutorAddresses` | `deployment/changesets/executor_state_inputs.go:162` | [#executor-job-drift-detection](#executor-job-drift-detection) |
| `sourcereader.Service` readiness clocks | behavior-changed | `lastSuccessfulQuery\|lastCompleteScan\|lastFinalityCheck` | `verifier/pkg/sourcereader/service.go:89` | [#readiness-staleness-precision](#readiness-staleness-precision) |
| `eventuallytimeout.Analyzer` | added | `eventuallytimeout` | `tools/eventuallytimeout/analyzer.go:31` | [#eventually-timeout-lint](#eventually-timeout-lint) |

## Breaking Changes

*No breaking changes.*

## New Features / Additions

### Executor job drift detection

`ExecutorPoolInputFromState` treats differing `SourceExecutorAddresses` maps across jobs in the same executor pool as drift. Previously it collected the union of source-only selectors without validating that the addresses agreed, allowing datastore iteration order and incomplete job updates to hide divergent configuration.

### Readiness staleness precision

`Service` records `lastSuccessfulQuery`, `lastCompleteScan`, and `lastFinalityCheck` with `time.Now().UnixNano()`, and `staleFor` reconstructs timestamps with nanosecond precision. Previously, truncating to whole seconds could make a one-second threshold report stale after only a few milliseconds when the clock crossed a second boundary.

The Prometheus last-successful-poll timestamp remains expressed in Unix seconds. No persisted representation changes because these readiness clocks are in-memory only.

### Eventually timeout lint

`just lint` now runs `lint-eventuallytimeout`, which checks `assert` and `require` calls to `Eventually`, `Eventuallyf`, `EventuallyWithT`, and `EventuallyWithTf`. Compile-time-constant timeouts below ten seconds are rejected; dynamic timeouts such as `tests.WaitTimeout(t)` remain supported.

All existing waits of five seconds or less now use `tests.WaitTimeout(t)`. Two panic-recovery tests replace fixed sleeps with condition-based polling, and the mature-chain start-block test compares the actual second-precision EVM header time used by production code.

## Compatibility & Requirements

- **Public APIs:** unchanged.
- **Configuration and persisted state:** unchanged.
- **Operational behavior:** readiness staleness is more accurate, especially for explicitly short thresholds.
- **Development:** new constant `Eventually` timeouts must be at least ten seconds or use the shared test timeout helper.

## References

- Follow-up to PR: https://github.com/smartcontractkit/chainlink-ccv/pull/1619
- Review comment: https://github.com/smartcontractkit/chainlink-ccv/pull/1619#discussion_r4647961673
- Prior changelog: `changelog/2026-11-20_executor_source_addresses.md`.
