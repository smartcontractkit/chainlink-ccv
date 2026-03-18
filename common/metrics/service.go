package metrics

import (
	"context"

	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
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
	labeler = labeler.With(ServiceNameLabel, serviceName)
	s := &serviceMetrics{
		Labeler:             labeler,
		serviceStartedGauge: serviceStartedGauge,
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
