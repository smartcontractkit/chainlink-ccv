package metricsgolden_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common/metrics/metricsgolden"
)

func TestCompare(t *testing.T) {
	base := metricsgolden.Metric{
		Name:    "storage_duration_seconds",
		Kind:    "Float64Histogram",
		Unit:    "s",
		Buckets: []float64{0.1, 1},
		Labels:  []string{"errored", "operation"},
	}

	tests := []struct {
		name    string
		head    func(m metricsgolden.Metric) []metricsgolden.Metric
		reasons []string
	}{
		{
			name: "no change",
			head: func(m metricsgolden.Metric) []metricsgolden.Metric { return []metricsgolden.Metric{m} },
		},
		{
			name:    "metric removed",
			head:    func(metricsgolden.Metric) []metricsgolden.Metric { return nil },
			reasons: []string{"metric removed"},
		},
		{
			name: "kind changed",
			head: func(m metricsgolden.Metric) []metricsgolden.Metric {
				m.Kind = "Int64Histogram"
				return []metricsgolden.Metric{m}
			},
			reasons: []string{"kind changed from Float64Histogram to Int64Histogram"},
		},
		{
			name: "unit changed",
			head: func(m metricsgolden.Metric) []metricsgolden.Metric {
				m.Unit = "ms"
				return []metricsgolden.Metric{m}
			},
			reasons: []string{`unit changed from "s" to "ms"`},
		},
		{
			name: "buckets changed",
			head: func(m metricsgolden.Metric) []metricsgolden.Metric {
				m.Buckets = []float64{0.1, 1, 10}
				return []metricsgolden.Metric{m}
			},
			reasons: []string{"buckets changed from [0.1 1] to [0.1 1 10]"},
		},
		{
			name: "label removed",
			head: func(m metricsgolden.Metric) []metricsgolden.Metric {
				m.Labels = []string{"operation"}
				return []metricsgolden.Metric{m}
			},
			reasons: []string{`label "errored" removed`},
		},
		{
			name: "label and metric added, description changed",
			head: func(m metricsgolden.Metric) []metricsgolden.Metric {
				m.Labels = []string{"errored", "operation", "query"}
				m.Description = "new description"
				return []metricsgolden.Metric{m, {Name: "new_total", Kind: "Int64Counter"}}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var reasons []string
			baseFile := metricsgolden.File{"svc": {base}}
			headFile := metricsgolden.File{"svc": tc.head(base)}
			for _, v := range metricsgolden.Compare(baseFile, headFile) {
				require.Equal(t, "svc", v.Target)
				require.Equal(t, base.Name, v.Metric)
				reasons = append(reasons, v.Reason)
			}
			require.Equal(t, tc.reasons, reasons)
		})
	}
}

func TestCompareTargets(t *testing.T) {
	m := metricsgolden.Metric{Name: "a_total", Kind: "Int64Counter"}

	removed := metricsgolden.Compare(metricsgolden.File{"svc": {m}}, metricsgolden.File{})
	require.Len(t, removed, 1)
	require.Equal(t, "svc: a_total: metric removed", removed[0].String())

	require.Empty(t, metricsgolden.Compare(metricsgolden.File{}, metricsgolden.File{"svc": {m}}), "new target is allowed")
}

func TestMarshalIsStable(t *testing.T) {
	metrics := []metricsgolden.Metric{
		{Name: "b_total", Kind: "Int64Counter", Labels: []string{"z", "a", "a"}},
		{Name: "a_total", Kind: "Int64Counter"},
	}
	a := metricsgolden.File{"y": metrics, "x": metrics}
	b := metricsgolden.File{"x": {metrics[1], metrics[0]}, "y": {metrics[1], metrics[0]}}

	outA, err := metricsgolden.Marshal(a)
	require.NoError(t, err)
	outB, err := metricsgolden.Marshal(b)
	require.NoError(t, err)
	require.Equal(t, string(outA), string(outB))
	require.Less(t, strings.Index(string(outA), `"x"`), strings.Index(string(outA), `"y"`))
	require.Contains(t, string(outA), `"labels": [
        "a",
        "z"
      ]`)
	require.Contains(t, string(outA), `"labels": []`)

	parsed, err := metricsgolden.Parse(outA)
	require.NoError(t, err)
	require.Len(t, parsed, 2)
}
