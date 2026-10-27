# Add metrics golden files and an add-only CI check

## Executive Summary

- Adds a golden file (`testdata/metrics.golden.json`) for each package that creates OTel metrics. The file records the name, kind, unit, description, buckets, and label keys of each instrument.
- Adds a CI workflow that fails when the golden files do not match the code, or when a PR removes or changes a metric or label.
- Dashboards and alerts depend on metric names, labels, and buckets. Before this change, no test found a change that broke them.
- Affects the aggregator, verifier, executor, indexer, `common/metrics`, and `common/jd/lifecycle`. Test and CI change only. No runtime behavior changes.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `metricsgolden.Metric`, `metricsgolden.Compare` | added | `metricsgolden\.` | `common/metrics/metricsgolden/metricsgolden.go:18` | [#golden-file-format-and-compare](#golden-file-format-and-compare) |
| `metricstest.Snapshot`, `metricstest.CallAll`, `metricstest.AssertGolden` | added | `metricstest\.` | `common/metrics/metricstest/metricstest.go:29` | [#test-helpers](#test-helpers) |
| `TestMetricsGolden` in each metrics package | added | `TestMetricsGolden` | `aggregator/pkg/monitoring/metrics_golden_test.go` | [#test-helpers](#test-helpers) |
| `tools/metricsgolden/cmd/metricsgolden` | added | `metricsgolden -base` | `tools/metricsgolden/cmd/metricsgolden/main.go` | [#ci-check](#ci-check) |
| `just metrics-golden-update`, `metrics-golden-verify`, `metrics-golden-check` | added | `metrics-golden-` | `Justfile:98` | [#ci-check](#ci-check) |
| `.github/workflows/metrics-golden.yaml` | added | `metrics-golden.yaml` | `.github/workflows/metrics-golden.yaml` | [#ci-check](#ci-check) |

## Breaking Changes

*No breaking changes.*

## New Features / Additions

### Golden file format and compare

- `metricsgolden.Metric` is one entry in a golden file. `Marshal` sorts the entries and the labels, so that the diff is stable.
- `metricsgolden.Compare(base, head)` returns a `Violation` for each of these changes:
  - A metric is removed.
  - The kind, unit, or buckets of a metric change.
  - A label is removed.
- New metrics, new labels, and description changes are allowed.

### Test helpers

- `metricstest.Snapshot(t, views, exercise, unrecorded...)` sets the beholder meter to a recording meter and an OTel `ManualReader`. Then it runs `exercise`. No production code changes are necessary.
- `metricstest.CallAll(t, target, args, skip...)` calls each exported method of a metrics type one time with zero-value arguments. Thus, each instrument records one value and its label keys.
- `Snapshot` fails if an instrument records no value. Put instruments that no code records in `unrecorded`. Today this list has one item: `executor_get_ccv_info_total`.
- `metricstest.AssertGolden(t, got)` compares the result with `testdata/metrics.golden.json`. When the files differ, it prints the breaking changes. Set `UPDATE_METRICS_GOLDEN=1` to write the file.

Golden tests:

| Package | Golden file |
|---|---|
| `aggregator/pkg/monitoring` | `aggregator/pkg/monitoring/testdata/metrics.golden.json` |
| `verifier/pkg/monitoring` | `verifier/pkg/monitoring/testdata/metrics.golden.json` |
| `executor/pkg/monitoring` | `executor/pkg/monitoring/testdata/metrics.golden.json` |
| `indexer/pkg/monitoring` | `indexer/pkg/monitoring/testdata/metrics.golden.json` |
| `common/metrics` | `common/metrics/testdata/metrics.golden.json` |
| `common/jd/lifecycle` | `common/jd/lifecycle/testdata/metrics.golden.json` |

### CI check

| Command | Purpose |
|---|---|
| `just metrics-golden-update` | Regenerates all golden files. |
| `just metrics-golden-verify` | Regenerates the golden files. Fails if they differ from the committed files. |
| `just metrics-golden-check [base] [allow_breaking]` | Checks out `base` (default `origin/main`) in a temporary git worktree. Fails if a metric or label is removed or changed since `base`. |

- The `metrics-golden` workflow runs `metrics-golden-verify`, then `metrics-golden-check` against the PR base commit.
- The PR label `metrics-breaking-change` lets an intended removal pass. A reviewer must approve it.
- `.gitattributes` marks the golden files as `linguist-generated`, so GitHub collapses them in the PR diff.

## Migration Guide

When you change a metric:

1. Change the code.
2. Run `just metrics-golden-update`.
3. Review the golden file diff, and commit it with the code.
4. If you add a new metrics package, add a `TestMetricsGolden` test with `metricstest.Snapshot` and `metricstest.AssertGolden`.

```go
func TestMetricsGolden(t *testing.T) {
	got := metricstest.Snapshot(t, monitoring.MetricViews(), func() {
		m, err := monitoring.InitMetrics()
		require.NoError(t, err)
		metricstest.CallAll(t, monitoring.NewIndexerMetricLabeler(metrics.NewLabeler(), m), nil, "With")
	})
	metricstest.AssertGolden(t, got)
}
```

To remove or rename a metric, keep the old metric with a deprecation comment. Remove it later in a separate PR that has the `metrics-breaking-change` label.

## Compatibility & Requirements

- The snapshot does not record labels that callers add at run time through `Labeler.With`.
- Metrics from dependencies, for example the chainlink-common `db_*` metrics, are not in the golden files.
