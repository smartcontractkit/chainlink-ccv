# Standalone executors initialize only assigned chains

## Executive Summary

- Standalone executor startup now ignores pool-wide `chain_configuration` entries whose `executor_pool` does not contain the local `executor_id`.
- This prevents chains assigned to other operators, and chain families the executor does not serve, from causing expected `executor.StartupSkips` degradation.
- Assigned chains retain their complete executor pools for leader election, and failures on assigned chains still degrade health.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `executor.Factory.Start` (`cmd/executor`) | behavior-changed | `NewFactory\(\)` | `cmd/executor/service.go:158` | [#standalone-startup-filtering](#standalone-startup-filtering) |

## Breaking Changes

*No breaking changes.*

## Standalone startup filtering

After decoding, validating, and normalizing a standalone job spec, `Factory.Start` removes chain entries that do not include its `executor_id` in `executor_pool`. It then builds accessors, leader-election state, indexer streaming, balance readers, and chain inspection only from the assigned entries.

Unassigned entries are intentionally ignored rather than recorded as startup skips. A job with no assigned chains still fails startup because its leader-elector chain map is empty. Existing pool-wide job specs require no regeneration, and CL-mode executor construction is unchanged.
