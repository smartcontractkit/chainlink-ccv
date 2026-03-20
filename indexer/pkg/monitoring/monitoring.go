package monitoring

import (
	"context"
	"fmt"

	"github.com/grafana/pyroscope-go"

	commonmetrics "github.com/smartcontractkit/chainlink-ccv/common/metrics"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

var _ common.IndexerMonitoring = (*IndexerBeholderMonitoring)(nil)

type IndexerBeholderMonitoring struct {
	metrics common.IndexerMetricLabeler
	commonmetrics.ServiceMetrics
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

	serviceMetrics, err := commonmetrics.NewServiceMetrics(metrics.NewLabeler(), "indexer")
	if err != nil {
		return nil, fmt.Errorf("failed to create service metrics: %w", err)
	}

	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "indexer",
		ServerAddress:   "http://pyroscope:4040",
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
		metrics:        NewIndexerMetricLabeler(metrics.NewLabeler(), indexerMetrics),
		ServiceMetrics: serviceMetrics,
	}, nil
}

func (i *IndexerBeholderMonitoring) Metrics() common.IndexerMetricLabeler {
	return i.metrics
}

// noopServiceMetrics implements commonmetrics.ServiceMetrics with no-op behavior for noop monitoring.
type noopServiceMetrics struct{}

func (noopServiceMetrics) RecordServiceStarted(context.Context) {}

// NoopIndexerMonitoring provides a no-op implementation of IndexerMonitoring.
type NoopIndexerMonitoring struct {
	noop common.IndexerMetricLabeler
	commonmetrics.ServiceMetrics
}

// NewNoopIndexerMonitoring creates a new noop monitoring instance.
func NewNoopIndexerMonitoring() common.IndexerMonitoring {
	return &NoopIndexerMonitoring{
		noop:           NewNoopIndexerMetricLabeler(),
		ServiceMetrics: noopServiceMetrics{},
	}
}

func (n *NoopIndexerMonitoring) Metrics() common.IndexerMetricLabeler {
	return n.noop
}
