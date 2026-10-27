package metricsgolden_test

import (
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
			for _, v := range metricsgolden.Compare([]metricsgolden.Metric{base}, tc.head(base)) {
				require.Equal(t, base.Name, v.Metric)
				reasons = append(reasons, v.Reason)
			}
			require.Equal(t, tc.reasons, reasons)
		})
	}
}

func TestMarshalIsStable(t *testing.T) {
	a := []metricsgolden.Metric{
		{Name: "b_total", Kind: "Int64Counter", Labels: []string{"z", "a", "a"}},
		{Name: "a_total", Kind: "Int64Counter"},
	}
	b := []metricsgolden.Metric{a[1], a[0]}

	outA, err := metricsgolden.Marshal(a)
	require.NoError(t, err)
	outB, err := metricsgolden.Marshal(b)
	require.NoError(t, err)
	require.Equal(t, string(outA), string(outB))
	require.Contains(t, string(outA), `"labels": [
      "a",
      "z"
    ]`)
	require.Contains(t, string(outA), `"labels": []`)
}
