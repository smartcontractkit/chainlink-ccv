package lifecycle_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common/jd/lifecycle"
	"github.com/smartcontractkit/chainlink-ccv/common/metrics/metricstest"
)

// TestMetricsGolden fails when a metric or label changes. See common/metrics/metricsgolden.
func TestMetricsGolden(t *testing.T) {
	got := metricstest.Snapshot(t, nil, func() {
		m, err := lifecycle.InitMetrics()
		require.NoError(t, err)
		metricstest.CallAll(t, m, nil)
	})
	metricstest.AssertGolden(t, got)
}
