# Add a metrics golden file and an add-only CI check

## Executive Summary

- Adds one golden file (`tools/metricsgolden/registry/testdata/metrics.golden.json`) for all packages that create OTel metrics. The file records the name, kind, unit, description, buckets, and label keys of each instrument, by target.
- A registry (`tools/metricsgolden/registry`) lists these packages. One test snapshots all of them.
- Adds CI steps that fail when the golden file does not match the code, or when a PR removes or changes a metric or label.
- Dashboards and alerts depend on metric names, labels, and buckets. Before this change, no test found a change that broke them.
- Affects the aggregator, verifier, executor, indexer, `common/metrics`, and `common/jd/lifecycle`. Test and CI change only. No runtime behavior changes.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `metricsgolden.File`, `metricsgolden.Metric`, `metricsgolden.Compare` | added | `metricsgolden\.` | `common/metrics/metricsgolden/metricsgolden.go:15` | [#golden-file-format-and-compare](#golden-file-format-and-compare) |
| `metricstest.Snapshot`, `metricstest.CallAll`, `metricstest.AssertGolden` | added | `metricstest\.` | `common/metrics/metricstest/metricstest.go:29` | [#test-helpers](#test-helpers) |
| `registry.Targets`, `registry.Target` | added | `registry\.Targets\b` | `tools/metricsgolden/registry/registry.go:36` | [#registry](#registry) |
| `tools/metricsgolden/cmd/metricsgolden` | added | `metricsgolden -base` | `tools/metricsgolden/cmd/metricsgolden/main.go` | [#ci-check](#ci-check) |
| `just metrics-golden-update`, `metrics-golden-verify`, `metrics-golden-check` | added | `metrics-golden-` | `Justfile:97` | [#ci-check](#ci-check) |
| `Repo Hygiene Checks` metrics steps | added | `metrics-golden-` | `.github/workflows/repo-hygiene.yaml` | [#ci-check](#ci-check) |

## Breaking Changes

*No breaking changes.*

## New Features / Additions

### Golden file format and compare

- `metricsgolden.File` maps a target name to its `[]metricsgolden.Metric`. `Marshal` sorts the targets, the metrics, and the labels, so that the diff is stable.
- `metricsgolden.Compare(base, head)` returns a `Violation` for each of these changes:
  - A target or a metric is removed.
  - The kind, unit, or buckets of a metric change.
  - A label is removed.
- New targets, new metrics, new labels, and description changes are allowed. Each `Violation` names the target.

### Test helpers

- `metricstest.Snapshot(t, views, exercise, unrecorded...)` sets the beholder meter to a recording meter and an OTel `ManualReader`. Then it runs `exercise`. No production code changes are necessary.
- `metricstest.CallAll(t, target, args, skip...)` calls each exported method of a metrics type one time with zero-value arguments. Thus, each instrument records one value and its label keys.
- `Snapshot` fails if an instrument records no value. Put instruments that no code records in `unrecorded`. Today this list has one item: `executor_get_ccv_info_total`.
- `metricstest.AssertGolden(t, path, got)` compares a `metricsgolden.File` with the golden file at `path`. When the files differ, it prints the breaking changes. Set `UPDATE_METRICS_GOLDEN=1` to write the file.

### Registry

`tools/metricsgolden/registry.Targets` lists each package that creates metrics. Each `Target` has a `Name` (the key in the golden file), a `Package` directory, the `Views` of the service, an `Exercise` function, and an optional `Unrecorded` list.

| Target | Package |
|---|---|
| `aggregator` | `aggregator/pkg/monitoring` |
| `verifier` | `verifier/pkg/monitoring` |
| `executor` | `executor/pkg/monitoring` |
| `indexer` | `indexer/pkg/monitoring` |
| `common_service` | `common/metrics` |
| `jd_lifecycle` | `common/jd/lifecycle` |

- `TestMetricsGolden` snapshots all targets and compares them with one golden file.
- `TestAllMetricPackagesRegistered` fails if a non-test file calls `beholder.GetMeter()` in a package that has no `Target`.

### CI check

| Command | Purpose |
|---|---|
| `just metrics-golden-update` | Regenerates the golden file. |
| `just metrics-golden-verify` | Regenerates the golden file. Fails if it differs from the committed file. |
| `just metrics-golden-check [base] [allow_breaking]` | Reads the golden file of `base` (default `origin/main`) with `git show`. Fails if a metric or label is removed or changed since `base`. If `base` has no golden file, the check passes. |

- The `Repo Hygiene Checks` workflow runs `metrics-golden-verify`, then `metrics-golden-check` against the PR base commit. The second step runs only on pull requests.
- The PR label `metrics-breaking-change` lets an intended removal pass. A reviewer must approve it.
- `.gitattributes` marks the golden file as `linguist-generated`, so GitHub collapses them in the PR diff.

## Migration Guide

When you change a metric:

1. Change the code.
2. Run `just metrics-golden-update`.
3. Review the golden file diff, and commit it with the code.
4. If you add a new package that creates metrics, add a `Target` to `tools/metricsgolden/registry/registry.go`. `TestAllMetricPackagesRegistered` fails until you do.

```go
{
	Name:    "indexer",
	Package: "indexer/pkg/monitoring",
	Views:   idxmonitoring.MetricViews,
	Exercise: func(t *testing.T) {
		m, err := idxmonitoring.InitMetrics()
		require.NoError(t, err)
		metricstest.CallAll(t, idxmonitoring.NewIndexerMetricLabeler(metrics.NewLabeler(), m), nil, "With")
	},
},
```

To remove or rename a metric, keep the old metric with a deprecation comment. Remove it later in a separate PR that has the `metrics-breaking-change` label.

## Compatibility & Requirements

- The snapshot does not record labels that callers add at run time through `Labeler.With`.
- Metrics from dependencies, for example the chainlink-common `db_*` metrics, are not in the golden file.
