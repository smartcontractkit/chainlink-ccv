package monitoring

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const configInstrument = "beholder.config.info"

func TestConfigRecorder_RecordsClientConfig(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	prev := beholder.GetClient()
	client := *beholder.NewNoopClient()
	client.Meter = provider.Meter("monitoringtest")
	client.Config = beholder.Config{
		ChipIngressEmitterEnabled: true,
		TraceSampleRatio:          0.5,
	}
	beholder.SetClient(&client)
	t.Cleanup(func() { beholder.SetClient(prev) })

	recorder, err := StartConfigRecorder(t.Context(), logger.Test(t))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, recorder.Close()) })

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	var gauge []metricdata.DataPoint[int64]
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != configInstrument {
				continue
			}
			require.Equal(t, "{info}", m.Unit)
			data, ok := m.Data.(metricdata.Gauge[int64])
			require.True(t, ok, "beholder config info must be an Int64Gauge")
			gauge = data.DataPoints
		}
	}

	require.Len(t, gauge, 1, "the config is recorded once at start")
	require.EqualValues(t, 1, gauge[0].Value)

	attrs := gauge[0].Attributes
	chip, ok := attrs.Value("chip_ingress_enabled")
	require.True(t, ok)
	require.True(t, chip.AsBool(), "attributes come from the client's own config")

	ratio, ok := attrs.Value("trace_sample_ratio")
	require.True(t, ok)
	require.InDelta(t, 0.5, ratio.AsFloat64(), 0.0001)
}

func TestConfigRecorder_CloseBeforeStart(t *testing.T) {
	recorder := NewConfigRecorder(logger.Test(t))

	require.NoError(t, recorder.Close(), "closing an unstarted recorder must not fail")
	require.NoError(t, recorder.Close(), "closing twice must not fail")
}

func TestWithDefaultServiceName(t *testing.T) {
	t.Run("defaults when the operator set none", func(t *testing.T) {
		in := map[string]string{"ccip_env": "devenv"}
		got := WithDefaultServiceName(in, "aggregator")

		require.Equal(t, "aggregator", got[serviceNameAttribute])
		require.Equal(t, "devenv", got["ccip_env"])
		require.NotContains(t, in, serviceNameAttribute, "the caller's map must not be mutated")
	})

	t.Run("operator value wins", func(t *testing.T) {
		in := map[string]string{serviceNameAttribute: "custom"}
		require.Equal(t, "custom", WithDefaultServiceName(in, "aggregator")[serviceNameAttribute])
	})

	t.Run("handles nil", func(t *testing.T) {
		require.Equal(t, "indexer", WithDefaultServiceName(nil, "indexer")[serviceNameAttribute])
	})
}
