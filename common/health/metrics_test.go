package health

import (
	"context"
	"errors"
	"sync"
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

// recorded is one collection of the instruments the recorder writes.
type recorded struct {
	statuses map[string]int64
	uptime   float64
	version  float64
}

// installCollectingMeter points the Beholder meter at a manual reader and returns the reader.
func installCollectingMeter(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	prev := beholder.GetClient()
	client := *beholder.NewNoopClient()
	client.Meter = provider.Meter("healthtest")
	beholder.SetClient(&client)
	t.Cleanup(func() { beholder.SetClient(prev) })

	return reader
}

func startRecorder(t *testing.T, manager *Manager) *MetricsRecorder {
	t.Helper()
	recorder, err := NewMetricsRecorder(logger.Test(t), manager)
	require.NoError(t, err)
	require.NoError(t, recorder.Start(t.Context()))
	t.Cleanup(func() { require.NoError(t, recorder.Close()) })
	return recorder
}

func collect(t *testing.T, reader *sdkmetric.ManualReader) recorded {
	t.Helper()

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	out := recorded{statuses: make(map[string]int64)}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case healthInstrument:
				gauge, ok := m.Data.(metricdata.Gauge[int64])
				require.True(t, ok, "health must be an Int64Gauge")
				for _, dp := range gauge.DataPoints {
					id, _ := dp.Attributes.Value(serviceIDAttribute)
					out.statuses[id.AsString()] = dp.Value
				}
			case uptimeInstrument:
				out.uptime = sumFloat(t, m.Data, "uptime_seconds")
			case versionInstrument:
				out.version = float64(sumInt(t, m.Data, "version"))
			}
		}
	}
	return out
}

// sumFloat returns the total of a float counter's data points, which is what a scrape reports.
func sumFloat(t *testing.T, data metricdata.Aggregation, name string) float64 {
	t.Helper()
	sum, ok := data.(metricdata.Sum[float64])
	require.True(t, ok, "%s must be a Float64Counter", name)
	total := 0.0
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	return total
}

// sumInt returns the total of an int counter's data points.
func sumInt(t *testing.T, data metricdata.Aggregation, name string) int64 {
	t.Helper()
	sum, ok := data.(metricdata.Sum[int64])
	require.True(t, ok, "%s must be an Int64Counter", name)
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	return total
}

// resetVersionOnce makes the per-process version counter fresh for a test.
func resetVersionOnce() {
	versionOnce = sync.Once{}
}

func TestMetricsRecorder_HealthByComponent(t *testing.T) {
	resetVersionOnce()
	reader := installCollectingMeter(t)

	manager := NewManager(logger.Test(t))
	manager.Register(&mockHealthyComponent{name: "ready"})
	manager.Register(&mockDegradedComponent{name: "degraded"})
	manager.Register(&mockUnhealthyComponent{name: "not_ready"})

	startRecorder(t, manager)
	got := collect(t, reader)

	require.Equal(t, map[string]int64{"ready": 1, "degraded": 1, "not_ready": 0}, got.statuses)
	require.InDelta(t, metricsInterval.Seconds(), got.uptime, 0.001, "uptime accumulates one tick")
	require.EqualValues(t, 1, got.version, "version is recorded once at start")
}

func TestMetricsRecorder_EmptyManager(t *testing.T) {
	resetVersionOnce()
	reader := installCollectingMeter(t)

	startRecorder(t, NewManager(logger.Test(t)))
	got := collect(t, reader)

	require.Empty(t, got.statuses)
	require.InDelta(t, metricsInterval.Seconds(), got.uptime, 0.001)
}

func TestMetricsRecorder_VersionRecordedOncePerProcess(t *testing.T) {
	resetVersionOnce()
	reader := installCollectingMeter(t)

	manager := NewManager(logger.Test(t))
	manager.Register(&mockHealthyComponent{name: "ready"})

	// A JD job replacement rebuilds the recorder: version must not count the same build twice,
	// but uptime restarts on purpose, so a restart stays visible.
	first := startRecorder(t, manager)
	early := collect(t, reader)
	require.NoError(t, first.Close())

	startRecorder(t, manager)
	late := collect(t, reader)

	require.EqualValues(t, 1, early.version)
	require.EqualValues(t, 1, late.version, "version counts once per process, not once per recorder")
	// The counter is process-scoped by construction: the replacement adds to the same series
	// rather than restarting it. Only a process restart resets it, which is what makes restarts
	// visible, and unlike a clock it never counts time the service was not running.
	require.InDelta(t, 2*metricsInterval.Seconds(), late.uptime, 0.001)
}

func TestHealthStatusValue(t *testing.T) {
	require.EqualValues(t, 1, healthStatusValue(Ready))
	require.EqualValues(t, 1, healthStatusValue(Degraded))
	require.EqualValues(t, 0, healthStatusValue(NotReady))
}

func TestMetricsRecorder_CloseBeforeStart(t *testing.T) {
	resetVersionOnce()

	recorder, err := NewMetricsRecorder(logger.Test(t), NewManager(logger.Test(t)))
	require.NoError(t, err)

	require.NoError(t, recorder.Close(), "closing an unstarted recorder must not fail")
	require.NoError(t, recorder.Close(), "closing twice must not fail")
}
