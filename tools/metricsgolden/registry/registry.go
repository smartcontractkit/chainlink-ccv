// Package registry lists each package that creates OTel metrics, for the metrics golden file test.
// Add a Target when you add a package that gets a meter from beholder.
package registry

import (
	"testing"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	aggmonitoring "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/common/health"
	"github.com/smartcontractkit/chainlink-ccv/common/jd/lifecycle"
	commonmetrics "github.com/smartcontractkit/chainlink-ccv/common/metrics"
	"github.com/smartcontractkit/chainlink-ccv/common/metrics/metricstest"
	ccvmonitoring "github.com/smartcontractkit/chainlink-ccv/common/monitoring"
	execmonitoring "github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	idxmonitoring "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	vermonitoring "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

// Target is one package that creates metrics.
type Target struct {
	// Name is the key of the target in the golden file.
	Name string
	// Package is the directory of the package, relative to the repo root.
	Package string
	// Views are the views that the service gives to beholder. Nil if the service has none.
	Views func() []sdkmetric.View
	// Exercise creates the instruments and records one value on each of them.
	Exercise func(t *testing.T)
	// Unrecorded lists instruments that are created, but that no code records.
	Unrecorded []string
}

// Targets is the registry of packages that create metrics.
var Targets = []Target{
	{
		Name:    "aggregator",
		Package: "aggregator/pkg/monitoring",
		Views:   aggmonitoring.MetricViews,
		Exercise: func(t *testing.T) {
			m, err := aggmonitoring.InitMetrics()
			require.NoError(t, err)
			metricstest.CallAll(t, aggmonitoring.NewAggregatorMetricLabeler(metrics.NewLabeler(), m), nil, "With")
		},
	},
	{
		Name:    "verifier",
		Package: "verifier/pkg/monitoring",
		Views:   vermonitoring.MetricViews,
		Exercise: func(t *testing.T) {
			m, err := vermonitoring.InitMetrics()
			require.NoError(t, err)
			metricstest.CallAll(t, vermonitoring.NewVerifierMetricLabeler(metrics.NewLabeler(), m), nil, "With")
		},
	},
	{
		Name:    "executor",
		Package: "executor/pkg/monitoring",
		Views:   execmonitoring.MetricViews,
		Exercise: func(t *testing.T) {
			m, err := execmonitoring.InitMetrics()
			require.NoError(t, err)
			metricstest.CallAll(t, execmonitoring.NewExecutorMetricLabeler(metrics.NewLabeler(), m), nil, "With")
		},
		Unrecorded: []string{"executor_get_ccv_info_total"},
	},
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
	{
		Name:    "common_service",
		Package: "common/metrics",
		Exercise: func(t *testing.T) {
			m, err := commonmetrics.NewServiceMetrics(metrics.NewLabeler(), "test_service")
			require.NoError(t, err)
			metricstest.CallAll(t, m, nil)
		},
	},
	{
		Name:    "jd_lifecycle",
		Package: "common/jd/lifecycle",
		Exercise: func(t *testing.T) {
			m, err := lifecycle.InitMetrics()
			require.NoError(t, err)
			metricstest.CallAll(t, m, nil)
		},
	},
	{
		Name:    "health",
		Package: "common/health",
		Exercise: func(t *testing.T) {
			manager := health.NewManager(logger.Test(t))
			manager.Register(health.NewStartupSkips("skipped"))
			recorder, err := health.NewMetricsRecorder(logger.Test(t), manager)
			require.NoError(t, err)
			require.NoError(t, recorder.Start(t.Context()))
			t.Cleanup(func() { require.NoError(t, recorder.Close()) })
		},
	},
	{
		Name:    "monitoring",
		Package: "common/monitoring",
		Exercise: func(t *testing.T) {
			recorder := ccvmonitoring.NewConfigRecorder(logger.Test(t))
			require.NoError(t, recorder.Start(t.Context()))
			t.Cleanup(func() { require.NoError(t, recorder.Close()) })
		},
	},
}
