package evm

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	lpmocks "github.com/smartcontractkit/chainlink-evm/pkg/logpoller/mocks"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifiermonitoring "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
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
	chainID, _ := points[0].Attributes.Value(attribute.Key("chainID"))
	chainFamily, _ := points[0].Attributes.Value(attribute.Key("chainFamily"))
	require.Equal(t, "1337", chainID.AsString())
	require.Equal(t, "evm", chainFamily.AsString())
}

// With the flag on, verifier_source_chain_latest_block carries the log poller's last processed block, so
// it stops moving when the log poller stalls. The observed wrapper must keep recording it.
func TestSourceChainLatestBlock_IsTheLogPollersLastProcessedBlock(t *testing.T) {
	lp := lpmocks.NewLogPoller(t)
	lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{BlockNumber: 777, FinalizedBlockNumber: 700, SafeBlockNumber: 750}, nil).Once()
	lp.EXPECT().GetBlocksRange(mock.Anything, []uint64{700}).Return([]logpoller.Block{{BlockNumber: 700}}, nil).Once()
	lpReader := readyLogPollerReader(sourceReaderCore{}, lp)

	monitor := verifiermonitoring.NewFakeVerifierMonitoring()
	observed, err := sourcereader.NewObservedSourceReader(lpReader, "verifier-1", protocol.ChainSelector(1337), monitor)
	require.NoError(t, err)

	latest, _, err := observed.LatestAndFinalizedBlock(t.Context())
	require.NoError(t, err)
	require.Equal(t, uint64(777), latest.Number)
	require.Equal(t, int64(777), monitor.Fake.SourceChainLatestBLock.Load())
}
