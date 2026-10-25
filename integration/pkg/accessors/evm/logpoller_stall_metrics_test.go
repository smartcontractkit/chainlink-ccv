package evm

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
)

// useInMemoryBeholder routes Beholder meters to a reader the test can collect from. It swaps the global
// client, so tests using it must not run in parallel.
func useInMemoryBeholder(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	previous := beholder.GetClient()
	beholder.SetClient(&beholder.Client{Meter: provider.Meter("test"), MeterProvider: provider})
	t.Cleanup(func() {
		beholder.SetClient(previous)
		require.NoError(t, provider.Shutdown(t.Context()))
	})
	return reader
}

func collectGauge(t *testing.T, reader *sdkmetric.ManualReader, name string) []metricdata.DataPoint[int64] {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &rm))
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != name {
				continue
			}
			gauge, ok := m.Data.(metricdata.Gauge[int64])
			require.True(t, ok, "%s must be an int64 gauge", name)
			return gauge.DataPoints
		}
	}
	return nil
}

// The standalone process serves no Prometheus endpoint, so a stalled log poller is only visible through
// this instrument. It fails if the log poller stops being handed the Beholder metrics.
func TestStandaloneLogPollerOpts_LastProcessedBlockIsEmittedThroughBeholder(t *testing.T) {
	reader := useInMemoryBeholder(t)
	cfg, err := newChainlinkEVMConfig(evmconfig.Info{
		ChainID: "1337",
		Nodes:   []evmconfig.Node{{HTTPUrl: "http://127.0.0.1:1"}},
	})
	require.NoError(t, err)
	opts, err := standaloneLogPollerOpts(logPollerInputs{chainID: big.NewInt(1337), config: cfg.EVM()})
	require.NoError(t, err)
	require.NotNil(t, opts.Metrics, "the log poller must be given metrics, or it emits nothing")
	opts.Metrics.RecordLastProcessedBlock(t.Context(), 4242)

	points := collectGauge(t, reader, "evm_log_poller_last_processed_block")
	require.Len(t, points, 1)
	require.Equal(t, int64(4242), points[0].Value)
}
