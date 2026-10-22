package verifier

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"

	commonmetrics "github.com/smartcontractkit/chainlink-ccv/common/metrics"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

// stalledRegistry hands out chains whose head fetch hangs until released, so no source reader service
// can write the chain's health while the test looks at it.
type stalledRegistry struct {
	idleRegistry
	release chan struct{}
}

func (r *stalledRegistry) GetAccessor(ctx context.Context, selector protocol.ChainSelector) (chainaccess.Accessor, error) {
	a, err := r.idleRegistry.GetAccessor(ctx, selector)
	if err != nil {
		return nil, err
	}
	return stalledAccessor{Accessor: a, release: r.release}, nil
}

type stalledAccessor struct {
	chainaccess.Accessor
	release chan struct{}
}

func (a stalledAccessor) SourceReader() (chainaccess.SourceReader, error) {
	return stalledSourceReader{release: a.release}, nil
}

type stalledSourceReader struct {
	idleSourceReader
	release chan struct{}
}

func (r stalledSourceReader) LatestAndFinalizedBlock(ctx context.Context) (*protocol.BlockHeader, *protocol.BlockHeader, error) {
	select {
	case <-r.release:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	return r.idleSourceReader.LatestAndFinalizedBlock(ctx)
}

// A selected chain is recorded unhealthy before its service exists, so its health series is present
// (and 0) even when no service ever writes it, instead of missing until one does.
func TestFactoryStart_SelectedChainIsUnhealthyUntilItsServiceReports(t *testing.T) {
	metrics := useInMemoryBeholder(t)
	_, dbURL := testutil.NewTestDBWithURL(t)
	setFactoryEnv(t, dbURL)
	f, reg, port := &factory{}, &stalledRegistry{release: make(chan struct{})}, freePort(t)

	require.NoError(t, startServingWith(t, f, reg, port))
	t.Cleanup(func() { release(t, f, &reg.idleRegistry) })
	t.Cleanup(func() { close(reg.release) })

	points := chainHealthyPoints(t, metrics)
	require.Len(t, points, 1, "the configured chain must have a health value before its service reports")
	selector, _ := points[0].Attributes.Value(attribute.Key(commonmetrics.ChainSelectorLabel))
	require.Equal(t, "5009297550715157269", selector.AsString())
	require.Equal(t, int64(0), points[0].Value)
}

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
		require.NoError(t, provider.Shutdown(context.Background()))
	})
	return reader
}

func chainHealthyPoints(t *testing.T, reader *sdkmetric.ManualReader) []metricdata.DataPoint[int64] {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &rm))
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name == commonmetrics.ChainHealthyGaugeName {
				gauge, ok := m.Data.(metricdata.Gauge[int64])
				require.True(t, ok)
				return gauge.DataPoints
			}
		}
	}
	return nil
}
