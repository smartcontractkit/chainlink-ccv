package metrics

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

const (
	// ServiceStartedGaugeName is the metric name used by all CCIP services.
	ServiceStartedGaugeName = "ccip_service_started"
	// ChainHealthyGaugeName tracks chain health across CCIP services.
	ChainHealthyGaugeName = "ccip_chain_healthy"
	// ServiceNameLabel is the label key for the service name (e.g. indexer, aggregator, verifier, executor).
	ServiceNameLabel = "service_name"
	// ChainSelectorLabel is the label key for the chain selector.
	ChainSelectorLabel = "chain_selector"
	// ChainNameLabel is the label key for the human-readable chain name.
	ChainNameLabel = "chain_name"
)

// ServiceMetrics provides standard service-level metrics that can be embedded
// in other metrics implementations.
type ServiceMetrics interface {
	// RecordServiceStarted records when the service is started.
	RecordServiceStarted(ctx context.Context)
	// RecordChainHealthy records whether a chain is healthy (1) or degraded/failed (0).
	RecordChainHealthy(ctx context.Context, selector protocol.ChainSelector, healthy bool)
}

type serviceMetrics struct {
	metrics.Labeler
	serviceName         string
	serviceStartedGauge metric.Int64Gauge
	chainHealthyGauge   metric.Int64Gauge
}

// NewServiceMetrics creates shared service-level metrics. serviceName is emitted as the
// "service_name" label so all services use the same gauge (e.g. ccip_service_started) with
// different label values (indexer, aggregator, verifier, executor).
func NewServiceMetrics(
	labeler metrics.Labeler,
	serviceName string,
) (ServiceMetrics, error) {
	serviceStartedGauge, err := beholder.GetMeter().Int64Gauge(
		ServiceStartedGaugeName,
		metric.WithDescription("Indicates when the service is started (1 = started)"),
	)
	if err != nil {
		return nil, err
	}
	chainHealthyGauge, err := beholder.GetMeter().Int64Gauge(
		ChainHealthyGaugeName,
		metric.WithDescription("Health status of configured chain (1 = healthy, 0 = degraded/failed)"),
	)
	if err != nil {
		return nil, err
	}
	labeler = labeler.With(ServiceNameLabel, serviceName)
	s := &serviceMetrics{
		Labeler:             labeler,
		serviceName:         serviceName,
		serviceStartedGauge: serviceStartedGauge,
		chainHealthyGauge:   chainHealthyGauge,
	}
	// Set the metrics to 0 right after the init to trigger visible switch between 0 and 1
	s.recordServiceMetric(context.Background(), 0)
	return s, nil
}

func (s *serviceMetrics) RecordServiceStarted(ctx context.Context) {
	s.recordServiceMetric(ctx, 1)
}

func (s *serviceMetrics) recordServiceMetric(ctx context.Context, value int64) {
	otelLabels := beholder.OtelAttributes(s.Labels).AsStringAttributes()
	s.serviceStartedGauge.Record(ctx, value, metric.WithAttributes(otelLabels...))
}

func (s *serviceMetrics) RecordChainHealthy(ctx context.Context, selector protocol.ChainSelector, healthy bool) {
	otelLabels := beholder.OtelAttributes(s.Labels).AsStringAttributes()
	var val int64
	if healthy {
		val = 1
	}
	attrs := append(otelLabels,
		attribute.String("service", s.serviceName),
		attribute.String(ChainSelectorLabel, selector.String()),
		attribute.String(ChainNameLabel, selector.ChainName()),
		attribute.String("chainSelector", selector.String()),
		attribute.String("chainName", selector.ChainName()),
	)
	s.chainHealthyGauge.Record(ctx, val, metric.WithAttributes(attrs...))
}
