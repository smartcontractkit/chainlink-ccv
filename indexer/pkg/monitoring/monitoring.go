package monitoring

import (
	"context"
	"fmt"

	commonmetrics "github.com/smartcontractkit/chainlink-ccv/common/metrics"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

var _ common.IndexerMonitoring = (*IndexerBeholderMonitoring)(nil)

type IndexerBeholderMonitoring struct {
	metrics common.IndexerMetricLabeler
	tracing tracing.Tracing
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

	return &IndexerBeholderMonitoring{
		metrics:        NewIndexerMetricLabeler(metrics.NewLabeler(), indexerMetrics),
		tracing:        tracing.NewTracing(beholder.GetTracer()),
		ServiceMetrics: serviceMetrics,
	}, nil
}

func (i *IndexerBeholderMonitoring) Metrics() common.IndexerMetricLabeler {
	return i.metrics
}

func (i *IndexerBeholderMonitoring) Tracing() tracing.Tracing {
	return i.tracing
}

// noopServiceMetrics implements commonmetrics.ServiceMetrics with no-op behavior for noop monitoring.
type noopServiceMetrics struct{}

func (noopServiceMetrics) RecordServiceStarted(context.Context) {}

// NoopIndexerMonitoring provides a no-op implementation of IndexerMonitoring.
type NoopIndexerMonitoring struct {
	noop    common.IndexerMetricLabeler
	tracing tracing.Tracing
	commonmetrics.ServiceMetrics
}

// NewNoopIndexerMonitoring creates a new noop monitoring instance.
func NewNoopIndexerMonitoring() common.IndexerMonitoring {
	return &NoopIndexerMonitoring{
		noop:           NewNoopIndexerMetricLabeler(),
		tracing:        tracing.NewTracing(beholder.GetTracer()),
		ServiceMetrics: noopServiceMetrics{},
	}
}

func (n *NoopIndexerMonitoring) Metrics() common.IndexerMetricLabeler {
	return n.noop
}

func (n *NoopIndexerMonitoring) Tracing() tracing.Tracing {
	return n.tracing
}
