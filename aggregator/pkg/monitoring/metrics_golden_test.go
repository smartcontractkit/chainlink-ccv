package monitoring_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/common/metrics/metricstest"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

// TestMetricsGolden fails when a metric or label changes. See common/metrics/metricsgolden.
func TestMetricsGolden(t *testing.T) {
	got := metricstest.Snapshot(t, monitoring.MetricViews(), func() {
		m, err := monitoring.InitMetrics()
		require.NoError(t, err)
		metricstest.CallAll(t, monitoring.NewAggregatorMetricLabeler(metrics.NewLabeler(), m), nil, "With")
	})
	metricstest.AssertGolden(t, got)
}
