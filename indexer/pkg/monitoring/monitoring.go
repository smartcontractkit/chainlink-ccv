package monitoring

import (
	"fmt"

	"github.com/grafana/pyroscope-go"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

var _ common.IndexerMonitoring = (*IndexerBeholderMonitoring)(nil)

type IndexerBeholderMonitoring struct {
	metrics common.IndexerMetricLabeler
}

func InitMonitoring(config beholder.Config) (common.IndexerMonitoring, error) {
	// Note: due to OTEL spec, all histogram buckets must be defined when the beholder client is created.
	config.MetricViews = MetricViews()

	// Create the beholder client
	client, err := beholder.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create beholder client: %w", err)
	}

	// Set the beholder client and global otel providers, so they don't have to be referenced elsewhere.
	beholder.SetClient(client)
	beholder.SetGlobalOtelProviders()

	// Initialize the indexer metrics
	indexerMetrics, err := InitMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize indexer metrics: %w", err)
	}

	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "indexer",
		ServerAddress:   "http://pyroscope:4040",
		Logger:          pyroscope.StandardLogger,
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileBlockDuration,
			pyroscope.ProfileMutexDuration,
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize pyroscope client: %w", err)
	}

	return &IndexerBeholderMonitoring{
		metrics: NewIndexerMetricLabeler(metrics.NewLabeler(), indexerMetrics),
	}, nil
}

func (i *IndexerBeholderMonitoring) Metrics() common.IndexerMetricLabeler {
	return i.metrics
}

// NoopIndexerMonitoring provides a no-op implementation of IndexerMonitoring.
type NoopIndexerMonitoring struct {
	noop common.IndexerMetricLabeler
}

// NewNoopIndexerMonitoring creates a new noop monitoring instance.
func NewNoopIndexerMonitoring() common.IndexerMonitoring {
	return &NoopIndexerMonitoring{
		noop: NewNoopIndexerMetricLabeler(),
	}
}

func (n *NoopIndexerMonitoring) Metrics() common.IndexerMetricLabeler {
	return n.noop
}
