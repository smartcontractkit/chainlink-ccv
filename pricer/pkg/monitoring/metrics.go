package monitoring

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// PricerMetrics provides all metrics for the pricer service.
type PricerMetrics struct {
	evmTickDurationSeconds metric.Float64Histogram
}

func InitMetrics() (*PricerMetrics, error) {
	pm := &PricerMetrics{}

	var err error
	pm.evmTickDurationSeconds, err = beholder.GetMeter().Float64Histogram(
		"pricer_evm_tick_duration_seconds",
		metric.WithDescription("Duration of EVM tick operations"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register EVM tick duration histogram: %w", err)
	}

	return pm, nil
}

// MetricViews defines histogram bucket boundaries for pricer metrics.
func MetricViews() []sdkmetric.View {
	return []sdkmetric.View{
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "pricer_evm_tick_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			}},
		),
	}
}

// PricerMetricLabeler wraps PricerMetrics with label support.
type PricerMetricLabeler struct {
	metrics.Labeler
	pm *PricerMetrics
}

func NewPricerMetricLabeler(labeler metrics.Labeler, pm *PricerMetrics) *PricerMetricLabeler {
	return &PricerMetricLabeler{
		Labeler: labeler,
		pm:      pm,
	}
}

func (p *PricerMetricLabeler) With(keyValues ...string) *PricerMetricLabeler {
	if p.pm == nil {
		return p
	}
	return &PricerMetricLabeler{p.Labeler.With(keyValues...), p.pm}
}

func (p *PricerMetricLabeler) RecordEVMTickDuration(ctx context.Context, duration time.Duration) {
	if p.pm == nil {
		return
	}
	otelLabels := beholder.OtelAttributes(p.Labels).AsStringAttributes()
	p.pm.evmTickDurationSeconds.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}
