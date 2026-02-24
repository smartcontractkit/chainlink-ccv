package monitoring

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// ExecutorMetrics provides all metrics for the verifier.
type ExecutorMetrics struct {
	// Latency
	messageExecutionLatency  metric.Float64Histogram
	messageGetCCVInfoLatency metric.Float64Histogram

	// Message Processing Counters
	messagesProcessedCounter        metric.Int64Counter
	messagesProcessingErrorsCounter metric.Int64Counter
	ccvInfoCacheHitsCounter         metric.Int64Counter
	ccvInfoCacheMissesCounter       metric.Int64Counter
	messageGetCCVInfoFailure        metric.Int64Counter
	messageExpiryCounter            metric.Int64Counter
	messageHeapSizeGauge            metric.Int64Gauge
	alreadyExecutedMessagesCounter  metric.Int64Counter

	// Heartbeat Metrics
	heartbeatSuccessCounter     metric.Int64Counter
	heartbeatFailureCounter     metric.Int64Counter
	lastHeartbeatTimestampGauge metric.Int64Gauge

	// Chain curse metric
	remoteChainCursed      metric.Int64Gauge
	localChainGlobalCursed metric.Int64Gauge
}

// InitMetrics initializes all verifier metrics.
func InitMetrics() (*ExecutorMetrics, error) {
	vm := &ExecutorMetrics{}
	var err error

	// Latency
	vm.messageExecutionLatency, err = beholder.GetMeter().Float64Histogram(
		"executor_message_execution_duration_seconds",
		metric.WithDescription("Full message lifecycle latency from source read to storage write"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register message e2e latency histogram: %w", err)
	}

	vm.messageGetCCVInfoLatency, err = beholder.GetMeter().Float64Histogram(
		"executor_get_ccv_info_latency_seconds",
		metric.WithDescription("Duration of the GetCCVSForMessage onchain call"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register get ccv latency histogram: %w", err)
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

	vm.ccvInfoCacheHitsCounter, err = beholder.GetMeter().Int64Counter(
		"executor_get_ccv_info_cache_hits_total",
		metric.WithDescription("Total number of cache hits for CCV info"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register ccv info cache hits counter: %w", err)
	}

	vm.ccvInfoCacheMissesCounter, err = beholder.GetMeter().Int64Counter(
		"executor_get_ccv_info_cache_misses_total",
		metric.WithDescription("Total number of cache misses for CCV info"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register ccv info cache misses counter: %w", err)
	}

	vm.messageGetCCVInfoFailure, err = beholder.GetMeter().Int64Counter(
		"executor_get_ccv_info_failure_total",
		metric.WithDescription("Total number of failure for CCV info onchain calls"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register ccv info failure counter: %w", err)
	}

	vm.messageExpiryCounter, err = beholder.GetMeter().Int64Counter(
		"executor_message_expiry_total",
		metric.WithDescription("Total number of messages expired and not attempted due to being too old"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register message expiry counter: %w", err)
	}

	vm.messageHeapSizeGauge, err = beholder.GetMeter().Int64Gauge(
		"executor_message_heap_size",
		metric.WithDescription("Current size of the heap of messages to potentially attempt"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register message heap size gauge: %w", err)
	}

	vm.alreadyExecutedMessagesCounter, err = beholder.GetMeter().Int64Counter(
		"executor_already_executed_messages_total",
		metric.WithDescription("Total number of times an executor skips a message due to it being already executed by a different executor"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register already executed messages counter: %w", err)
	}

	// Initialize heartbeat metrics
	vm.heartbeatSuccessCounter, err = beholder.GetMeter().Int64Counter(
		"executor_indexer_heartbeat_success_total",
		metric.WithDescription("Total number of successful heartbeats sent to indexer"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register heartbeat success counter: %w", err)
	}

	vm.heartbeatFailureCounter, err = beholder.GetMeter().Int64Counter(
		"executor_indexer_heartbeat_failure_total",
		metric.WithDescription("Total number of failed heartbeats to indexer"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register heartbeat failure counter: %w", err)
	}

	vm.lastHeartbeatTimestampGauge, err = beholder.GetMeter().Int64Gauge(
		"executor_indexer_last_heartbeat_timestamp",
		metric.WithDescription("Timestamp of the last successful heartbeat sent to indexer"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register last heartbeat timestamp gauge: %w", err)
	}

	vm.remoteChainCursed, err = beholder.GetMeter().Int64Gauge(
		"executor_remote_chain_cursed",
		metric.WithDescription("Specifies if local chain considers remote chain as cursed"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register remote chain cursed gauge: %w", err)
	}

	vm.localChainGlobalCursed, err = beholder.GetMeter().Int64Gauge(
		"executor_local_chain_global_cursed",
		metric.WithDescription("Specifies if local chain has global curse"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register remote chain cursed gauge: %w", err)
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

func (v *ExecutorMetricLabeler) RecordMessageExecutionLatency(ctx context.Context, duration time.Duration, destChainSelector protocol.ChainSelector) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messageExecutionLatency.Record(ctx, duration.Seconds(), metric.WithAttributes([]attribute.KeyValue{
		attribute.String("destChainSelector", destChainSelector.String()),
	}...), metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) IncrementMessagesProcessed(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messagesProcessedCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) IncrementMessagesProcessingFailed(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messagesProcessingErrorsCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) IncrementCCVInfoCacheHits(ctx context.Context, destChainSelector protocol.ChainSelector) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.ccvInfoCacheHitsCounter.Add(ctx, 1, metric.WithAttributes([]attribute.KeyValue{
		attribute.String("destChainSelector", destChainSelector.String()),
	}...), metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) IncrementCCVInfoCacheMisses(ctx context.Context, destChainSelector protocol.ChainSelector) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.ccvInfoCacheMissesCounter.Add(ctx, 1, metric.WithAttributes([]attribute.KeyValue{
		attribute.String("destChainSelector", destChainSelector.String()),
	}...), metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) RecordOfframpGetCCVsForMessageLatency(ctx context.Context, duration time.Duration, destChainSelector protocol.ChainSelector) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messageGetCCVInfoLatency.Record(ctx, duration.Seconds(), metric.WithAttributes([]attribute.KeyValue{
		attribute.String("destChainSelector", destChainSelector.String()),
	}...), metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) IncrementOfframpGetCCVsForMessageFailure(ctx context.Context, destChainSelector protocol.ChainSelector) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messageGetCCVInfoFailure.Add(ctx, 1, metric.WithAttributes([]attribute.KeyValue{
		attribute.String("destChainSelector", destChainSelector.String()),
	}...), metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) IncrementExpiredMessages(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messageExpiryCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) RecordMessageHeapSize(ctx context.Context, size int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messageHeapSizeGauge.Record(ctx, size, metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) IncrementAlreadyExecutedMessages(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.alreadyExecutedMessagesCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) IncrementHeartbeatSuccess(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.heartbeatSuccessCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) IncrementHeartbeatFailure(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.heartbeatFailureCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) SetLastHeartbeatTimestamp(ctx context.Context, timestamp int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.lastHeartbeatTimestampGauge.Record(ctx, timestamp, metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) SetRemoteChainCursed(ctx context.Context, localSelector, remoteSelector protocol.ChainSelector, cursed bool) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	otelLabels = append(otelLabels, attribute.String("localSelector", localSelector.String()))
	otelLabels = append(otelLabels, attribute.String("remoteSelector", remoteSelector.String()))
	var cursedInt int64
	if cursed {
		cursedInt = 1
	}
	v.vm.remoteChainCursed.Record(ctx, cursedInt, metric.WithAttributes(otelLabels...))
}

func (v *ExecutorMetricLabeler) SetLocalChainGlobalCursed(ctx context.Context, localSelector protocol.ChainSelector, globalCurse bool) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	otelLabels = append(otelLabels, attribute.String("localSelector", localSelector.String()))
	var cursedInt int64
	if globalCurse {
		cursedInt = 1
	}
	v.vm.localChainGlobalCursed.Record(ctx, cursedInt, metric.WithAttributes(otelLabels...))
}
