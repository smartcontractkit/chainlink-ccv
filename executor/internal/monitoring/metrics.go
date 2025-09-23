package monitoring

import (
	"context"

	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// ExecutorMetrics provides all metrics provided by the executor.
type ExecutorMetrics struct {
	uniqueMessagesCounter metric.Int64Counter
}

func MetricViews() []sdkmetric.View {
	return []sdkmetric.View{}
}

func InitMetrics() (em *ExecutorMetrics, err error) {
	em = &ExecutorMetrics{}

	return em, nil
}

type ExecutorMetricLabeler struct {
	metrics.Labeler
	em *ExecutorMetrics
}

func NewExecutorMetricLabeler(labeler metrics.Labeler, em *ExecutorMetrics) executor.MetricLabeler {
	return &ExecutorMetricLabeler{
		Labeler: labeler,
		em:      em,
	}
}

func (c *ExecutorMetricLabeler) With(keyValues ...string) executor.MetricLabeler {
	return &ExecutorMetricLabeler{c.Labeler.With(keyValues...), c.em}
}

func (c *ExecutorMetricLabeler) IncrementUniqueMessagesCounter(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.em.uniqueMessagesCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}
