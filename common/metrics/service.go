package metrics

import (
	"context"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
	"go.opentelemetry.io/otel/metric"
)

const (
	// ServiceStartedGaugeName is the metric name used by all CCIP services.
	ServiceStartedGaugeName = "ccip_service_started"
	// ServiceNameLabel is the label key for the service name (e.g. indexer, aggregator, verifier, executor).
	ServiceNameLabel = "service_name"
)

// ServiceMetrics provides standard service-level metrics that can be embedded
// in other metrics implementations.
type ServiceMetrics interface {
	// RecordServiceStarted records when the service is started.
	RecordServiceStarted(ctx context.Context)
}

type serviceMetrics struct {
	metrics.Labeler
	serviceStartedGauge metric.Int64Gauge
}

// NewServiceMetrics creates shared service-level metrics. serviceName is emitted as the
// "service_name" label so all services use the same gauge (e.g. ccip_service_started) with
// different label values (indexer, aggregator, verifier, executor).
func NewServiceMetrics(labeler metrics.Labeler, serviceName string) (ServiceMetrics, error) {
	serviceStartedGauge, err := beholder.GetMeter().Int64Gauge(
		ServiceStartedGaugeName,
		metric.WithDescription("Indicates when the service is started (1 = started)"),
	)
	if err != nil {
		return nil, err
	}
	labeler = labeler.With(ServiceNameLabel, serviceName)
	return &serviceMetrics{
		Labeler:             labeler,
		serviceStartedGauge: serviceStartedGauge,
	}, nil
}

func (s *serviceMetrics) RecordServiceStarted(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(s.Labels).AsStringAttributes()
	s.serviceStartedGauge.Record(ctx, 1, metric.WithAttributes(otelLabels...))
}
