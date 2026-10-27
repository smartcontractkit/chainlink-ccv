package metrics_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	commonmetrics "github.com/smartcontractkit/chainlink-ccv/common/metrics"
	"github.com/smartcontractkit/chainlink-ccv/common/metrics/metricstest"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

// TestMetricsGolden fails when a metric or label changes. See common/metrics/metricsgolden.
func TestMetricsGolden(t *testing.T) {
	got := metricstest.Snapshot(t, nil, func() {
		m, err := commonmetrics.NewServiceMetrics(metrics.NewLabeler(), "test_service")
		require.NoError(t, err)
		metricstest.CallAll(t, m, nil)
	})
	metricstest.AssertGolden(t, got)
}
