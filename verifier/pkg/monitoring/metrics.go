package monitoring

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// VerifierMetrics provides all metrics for the verifier.
type VerifierMetrics struct {
	// E2E Latency - North Star Metric
	messageE2ELatencyMilliseconds metric.Int64Histogram

	// Message Processing Counters
	messagesProcessedCounter   metric.Int64Counter
	messagesVerificationFailed metric.Int64Counter

	// Fine-Grained Latency Breakdown
	finalityWaitDurationMilliseconds        metric.Int64Histogram
	messageVerificationDurationMilliseconds metric.Int64Histogram
	storageWriteDurationMilliseconds        metric.Int64Histogram

	// Queue Health
	finalityQueueSizeGauge  metric.Int64Gauge
	ccvDataChannelSizeGauge metric.Int64Gauge

	// Error Tracking
	storageWriteErrorsCounter metric.Int64Counter

	// Chain State
	sourceChainLatestBlockGauge    metric.Int64Gauge
	sourceChainFinalizedBlockGauge metric.Int64Gauge
}

// InitMetrics initializes all verifier metrics.
func InitMetrics() (*VerifierMetrics, error) {
	vm := &VerifierMetrics{}
	var err error

	// E2E Latency
	vm.messageE2ELatencyMilliseconds, err = beholder.GetMeter().Int64Histogram(
		"verifier_message_e2e_latency_seconds",
		metric.WithDescription("Full message lifecycle latency from source read to storage write"),
		metric.WithUnit("milliseconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register message e2e latency histogram: %w", err)
	}

	// Message Processing Counters
	vm.messagesProcessedCounter, err = beholder.GetMeter().Int64Counter(
		"verifier_messages_processed_total",
		metric.WithDescription("Total number of successfully processed and stored messages"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register messages processed counter: %w", err)
	}

	vm.messagesVerificationFailed, err = beholder.GetMeter().Int64Counter(
		"verifier_messages_verification_failed_total",
		metric.WithDescription("Total number of messages that failed verification"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register messages verification failed counter: %w", err)
	}

	// Fine-Grained Latency Breakdown
	vm.finalityWaitDurationMilliseconds, err = beholder.GetMeter().Int64Histogram(
		"verifier_finality_wait_duration_seconds",
		metric.WithDescription("Time a message spent waiting in the finality queue"),
		metric.WithUnit("milliseconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register finality wait duration histogram: %w", err)
	}

	vm.messageVerificationDurationMilliseconds, err = beholder.GetMeter().Int64Histogram(
		"verifier_message_verification_duration_seconds",
		metric.WithDescription("Duration of the full VerifyMessage operation"),
		metric.WithUnit("milliseconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register message verification duration histogram: %w", err)
	}

	vm.storageWriteDurationMilliseconds, err = beholder.GetMeter().Int64Histogram(
		"verifier_storage_write_duration_seconds",
		metric.WithDescription("Duration of writing to offchain storage"),
		metric.WithUnit("milliseconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register storage write duration histogram: %w", err)
	}

	// Queue Health
	vm.finalityQueueSizeGauge, err = beholder.GetMeter().Int64Gauge(
		"verifier_finality_queue_size",
		metric.WithDescription("Current size of the finality queue"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register finality queue size gauge: %w", err)
	}

	vm.ccvDataChannelSizeGauge, err = beholder.GetMeter().Int64Gauge(
		"verifier_ccv_data_channel_size",
		metric.WithDescription("Current size of the CCV data channel buffer"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register ccv data channel size gauge: %w", err)
	}

	// Error Tracking
	vm.storageWriteErrorsCounter, err = beholder.GetMeter().Int64Counter(
		"verifier_storage_write_errors_total",
		metric.WithDescription("Total number of errors when writing to offchain storage"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register storage write errors counter: %w", err)
	}

	// Chain State
	vm.sourceChainLatestBlockGauge, err = beholder.GetMeter().Int64Gauge(
		"verifier_source_chain_latest_block",
		metric.WithDescription("Latest block number for a source chain"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register source chain latest block gauge: %w", err)
	}

	vm.sourceChainFinalizedBlockGauge, err = beholder.GetMeter().Int64Gauge(
		"verifier_source_chain_finalized_block",
		metric.WithDescription("Latest finalized block number for a source chain"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register source chain finalized block gauge: %w", err)
	}

	return vm, nil
}

// MetricViews defines histogram bucket boundaries for verifier metrics.
func MetricViews() []sdkmetric.View {
	return []sdkmetric.View{
		// E2E Latency - wider range for full message lifecycle (reading -> finality -> verification -> storage write)
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "verifier_message_e2e_latency_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.1, 0.5, 1, 2, 5, 10, 20, 30, 60, 90, 120, 180, 240, 300, 360, 420, 480, 540, 600, 900, 1200, 1800, 2400, 3000, 3600, 4200, 4800, 5400, 6000},
			}},
		),
		// Finality Wait
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "verifier_finality_wait_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{1, 5, 10, 20, 30, 60, 90, 120, 180, 240, 300, 360, 420, 480, 540, 600, 900, 1200, 1800, 2400, 3000, 3600, 4200, 4800, 5400, 6000},
			}},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "verifier_message_verification_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000},
			}},
		),
		// Storage Write
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "verifier_storage_write_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000},
			}},
		),
	}
}

var _ common.VerifierMetricLabeler = (*VerifierMetricLabeler)(nil)

// VerifierMetricLabeler wraps VerifierMetrics with label support.
type VerifierMetricLabeler struct {
	metrics.Labeler
	vm *VerifierMetrics
}

// NewVerifierMetricLabeler creates a new verifier metric labeler.
func NewVerifierMetricLabeler(labeler metrics.Labeler, vm *VerifierMetrics) common.VerifierMetricLabeler {
	return &VerifierMetricLabeler{
		Labeler: labeler,
		vm:      vm,
	}
}

func (v *VerifierMetricLabeler) With(keyValues ...string) common.VerifierMetricLabeler {
	return &VerifierMetricLabeler{v.Labeler.With(keyValues...), v.vm}
}

func (v *VerifierMetricLabeler) RecordMessageE2ELatency(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messageE2ELatencyMilliseconds.Record(ctx, duration.Milliseconds(), metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) IncrementMessagesProcessed(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messagesProcessedCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) IncrementMessagesVerificationFailed(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messagesVerificationFailed.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordFinalityWaitDuration(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.finalityWaitDurationMilliseconds.Record(ctx, duration.Milliseconds(), metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordMessageVerificationDuration(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messageVerificationDurationMilliseconds.Record(ctx, duration.Milliseconds(), metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordStorageWriteDuration(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.storageWriteDurationMilliseconds.Record(ctx, duration.Milliseconds(), metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordFinalityQueueSize(ctx context.Context, size int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.finalityQueueSizeGauge.Record(ctx, size, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordCCVDataChannelSize(ctx context.Context, size int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.ccvDataChannelSizeGauge.Record(ctx, size, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) IncrementStorageWriteErrors(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.storageWriteErrorsCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordSourceChainLatestBlock(ctx context.Context, blockNum int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.sourceChainLatestBlockGauge.Record(ctx, blockNum, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordSourceChainFinalizedBlock(ctx context.Context, blockNum int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.sourceChainFinalizedBlockGauge.Record(ctx, blockNum, metric.WithAttributes(otelLabels...))
}
