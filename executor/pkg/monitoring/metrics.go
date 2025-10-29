package monitoring

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// ExecutorMetrics provides all metrics for the verifier.
type ExecutorMetrics struct {
	// Latency
	messageExecutionLatency metric.Float64Histogram

	// Message Processing Counters
	messagesProcessedCounter        metric.Int64Counter
	messagesProcessingErrorsCounter metric.Int64Counter
}

// InitMetrics initializes all verifier metrics.
func InitMetrics() (*ExecutorMetrics, error) {
	vm := &ExecutorMetrics{}
	var err error

	// Latency
	vm.messageExecutionLatency, err = beholder.GetMeter().Float64Histogram(
		"executor_message_execution_duration_seconds",
		metric.WithDescription("Full message lifecycle latency from source read to storage write"),
		metric.WithUnit("milliseconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register message e2e latency histogram: %w", err)
	}

	// Message Processing Counters
	vm.messagesProcessedCounter, err = beholder.GetMeter().Int64Counter(
		"executor_messages_processed_total",
		metric.WithDescription("Total number of successfully processed and stored messages"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register messages processed counter: %w", err)
	}
	vm.messagesProcessingErrorsCounter, err = beholder.GetMeter().Int64Counter(
		"executor_messages_processing_errors_total",
		metric.WithDescription("Total number of messages failed to process"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register messages processing errors counter: %w", err)
	}

	return vm, nil
}

// MetricViews defines histogram bucket boundaries for verifier metrics.
func MetricViews() []sdkmetric.View {
	return []sdkmetric.View{
		// Execution latency from the report timestamp
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "executor_message_execution_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{1, 2, 5, 10, 15, 30, 60, 120, 180, 300, 600, 900, 1200},
			}},
		),
	}
}

var _ executor.MetricLabeler = &ExecutorMetricLabeler{}

// ExecutorMetricLabeler wraps ExecutorMetrics with label support.
type ExecutorMetricLabeler struct {
	metrics.Labeler
	vm *ExecutorMetrics
}

// NewExecutorMetricLabeler creates a new executor metric labeler.
func NewExecutorMetricLabeler(labeler metrics.Labeler, vm *ExecutorMetrics) executor.MetricLabeler {
	return &ExecutorMetricLabeler{
		Labeler: labeler,
		vm:      vm,
	}
}

func (v *ExecutorMetricLabeler) With(keyValues ...string) executor.MetricLabeler {
	return &ExecutorMetricLabeler{v.Labeler.With(keyValues...), v.vm}
}

func (v *ExecutorMetricLabeler) RecordMessageExecutionLatency(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messageExecutionLatency.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) IncrementMessagesProcessed(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messagesProcessedCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) IncrementMessagesProcessingFailed(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messagesProcessingErrorsCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}
