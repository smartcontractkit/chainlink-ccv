# Multi-aggregator standalone verifier configs require consolidation

## Executive Summary

- `ApplyVerifierConfig` now rejects legacy per-aggregator jobs when its publish set includes a standalone verifier NOP and the committee has multiple aggregators.
- Standalone runs one job, so proposing separate jobs for multiple aggregators can replace the intended consolidated job and lose aggregator coverage.
- CL-mode and single-aggregator standalone publishing are unchanged, standalone NOPs outside `TargetNOPs` do not block a CL-only publish, and cleanup-only runs still accept the zero value.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `changesets.ApplyVerifierConfigInput.ConsolidateAggregators` | behavior-changed | `ConsolidateAggregators|consolidateAggregators` | `deployment/changesets/apply_verifier_config.go:53` | [#validation-behavior](#validation-behavior) |

## Breaking Changes

No Go API changes. Previously accepted unsafe multi-aggregator standalone inputs now fail precondition validation and job-spec construction.

### Validation behavior

Before, `ConsolidateAggregators: false` or an omitted `consolidateAggregators` generated one verifier job per aggregator for every NOP mode. After, a standalone target with multiple aggregators must use the single consolidated job that contains every aggregator connection.

The false setting remains valid for CL-mode NOPs and standalone NOPs with at most one aggregator, preserving existing single-aggregator Solana and Canton job specs. Validation examines only committee NOPs in the publish set. It does not reject legacy CL jobs because an untargeted NOP is standalone, and it does not affect runs with empty `ChainConfigs` that only clean up orphaned jobs.

## Migration Guide

Set the flag on standalone verifier publishes for committees with multiple aggregators:

```yaml
payload:
  consolidateAggregators: true
```

No changes are needed for CL-mode jobs, single-aggregator standalone jobs, executor configs, or standalone executor JD routing.

## References

- Example unsafe pipeline configuration and subsequent correction: https://github.com/smartcontractkit/chainlink-deployments/pull/21237
- Standalone executor JD routing: https://github.com/smartcontractkit/chainlink-ccv/pull/1590
