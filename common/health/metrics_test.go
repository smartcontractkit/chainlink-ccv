package health

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// mockDegradedComponent is ready but missing something, which /health reports as degraded.
type mockDegradedComponent struct {
	name string
}

func (m *mockDegradedComponent) Ready() error { return nil }

func (m *mockDegradedComponent) Degraded() error { return errors.New("one chain skipped") }

func (m *mockDegradedComponent) HealthReport() map[string]error { return map[string]error{} }

func (m *mockDegradedComponent) Name() string { return m.name }

// recordHealth installs a collecting meter, starts a recorder over manager, and returns the
// health gauge values keyed by service_id plus the uptime counter's value.
func recordHealth(t *testing.T, manager *Manager) (map[string]int64, float64) {
	t.Helper()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	prev := beholder.GetClient()
	client := *beholder.NewNoopClient()
	client.Meter = provider.Meter("healthtest")
	beholder.SetClient(&client)
	t.Cleanup(func() { beholder.SetClient(prev) })

	recorder, err := NewMetricsRecorder(logger.Test(t), manager)
	require.NoError(t, err)
	require.NoError(t, recorder.Start(t.Context()))
	t.Cleanup(func() { require.NoError(t, recorder.Close()) })

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	statuses := make(map[string]int64)
	var uptime float64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case healthInstrument:
				gauge, ok := m.Data.(metricdata.Gauge[int64])
				require.True(t, ok, "health must be an Int64Gauge")
				for _, dp := range gauge.DataPoints {
					id, _ := dp.Attributes.Value(serviceIDAttribute)
					statuses[id.AsString()] = dp.Value
				}
			case uptimeInstrument:
				sum, ok := m.Data.(metricdata.Sum[float64])
				require.True(t, ok, "uptime_seconds must be a Float64Counter")
				for _, dp := range sum.DataPoints {
					uptime = dp.Value
				}
			}
		}
	}
	return statuses, uptime
}

func TestMetricsRecorder_HealthByComponent(t *testing.T) {
	manager := NewManager()
	manager.Register(&mockHealthyComponent{name: "ready"})
	manager.Register(&mockDegradedComponent{name: "degraded"})
	manager.Register(&mockUnhealthyComponent{name: "not_ready"})

	statuses, uptime := recordHealth(t, manager)

	require.Equal(t, map[string]int64{"ready": 1, "degraded": 1, "not_ready": 0}, statuses)
	require.InDelta(t, metricsInterval.Seconds(), uptime, 0.001, "uptime accumulates one tick")
}

func TestMetricsRecorder_EmptyManager(t *testing.T) {
	statuses, uptime := recordHealth(t, NewManager())

	require.Empty(t, statuses)
	require.InDelta(t, metricsInterval.Seconds(), uptime, 0.001)
}

func TestHealthStatusValue(t *testing.T) {
	require.EqualValues(t, 1, healthStatusValue(Ready))
	require.EqualValues(t, 1, healthStatusValue(Degraded))
	require.EqualValues(t, 0, healthStatusValue(NotReady))
}

func TestMetricsRecorder_CloseBeforeStart(t *testing.T) {
	recorder, err := NewMetricsRecorder(logger.Test(t), NewManager())
	require.NoError(t, err)

	require.NoError(t, recorder.Close(), "closing an unstarted recorder must not fail")
	require.NoError(t, recorder.Close(), "closing twice must not fail")
}
