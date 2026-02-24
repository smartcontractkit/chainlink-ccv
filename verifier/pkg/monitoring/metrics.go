package monitoring

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// VerifierMetrics provides all metrics for the verifier.
type VerifierMetrics struct {
	// E2E Latency - North Star Metric
	messageE2ELatencySeconds metric.Float64Histogram

	// Message Processing Counters
	messagesProcessedCounter   metric.Int64Counter
	messagesVerificationFailed metric.Int64Counter

	// Fine-Grained Latency Breakdown
	finalityWaitDurationSeconds        metric.Float64Histogram
	messageVerificationDurationSeconds metric.Float64Histogram
	storageWriteDurationSeconds        metric.Float64Histogram

	// Queue Health
	finalityQueueSizeGauge  metric.Int64Gauge
	ccvDataChannelSizeGauge metric.Int64Gauge

	// Error Tracking
	storageWriteErrorsCounter metric.Int64Counter

	// Heartbeat Tracking
	heartbeatsSentCounter           metric.Int64Counter
	heartbeatsFailedCounter         metric.Int64Counter
	heartbeatDurationSeconds        metric.Float64Histogram
	verifierHeartbeatTimestamp      metric.Float64Gauge
	verifierHeartbeatSentChainHeads metric.Int64Gauge
	verifierHeartbeatChainHeads     metric.Int64Gauge
	verifierHeartbeatScore          metric.Float64Gauge

	// Chain State
	sourceChainLatestBlockGauge    metric.Int64Gauge
	sourceChainFinalizedBlockGauge metric.Int64Gauge
	finalityViolated               metric.Int64Gauge
	remoteChainCursed              metric.Int64Gauge
	localChainGlobalCursed         metric.Int64Gauge

	// Reorg Tracking
	reorgTrackedSeqNumsGauge metric.Int64Gauge

	// HTTP API Metrics
	httpActiveRequestsUpDownCounter metric.Int64UpDownCounter
	httpRequestCounter              metric.Int64Counter
	httpRequestDurationSeconds      metric.Float64Histogram

	// Storage Query Metrics
	storageQueryDurationSeconds metric.Float64Histogram
}

// InitMetrics initializes all verifier metrics.
func InitMetrics() (*VerifierMetrics, error) {
	vm := &VerifierMetrics{}
	var err error

	// E2E Latency
	vm.messageE2ELatencySeconds, err = beholder.GetMeter().Float64Histogram(
		"verifier_message_e2e_latency_seconds",
		metric.WithDescription("Full message lifecycle latency from source read to storage write"),
		metric.WithUnit("seconds"),
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
	vm.finalityWaitDurationSeconds, err = beholder.GetMeter().Float64Histogram(
		"verifier_finality_wait_duration_seconds",
		metric.WithDescription("Time a message spent waiting in the finality queue"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register finality wait duration histogram: %w", err)
	}

	vm.messageVerificationDurationSeconds, err = beholder.GetMeter().Float64Histogram(
		"verifier_message_verification_duration_seconds",
		metric.WithDescription("Duration of the full VerifyMessage operation"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register message verification duration histogram: %w", err)
	}

	vm.storageWriteDurationSeconds, err = beholder.GetMeter().Float64Histogram(
		"verifier_storage_write_duration_seconds",
		metric.WithDescription("Duration of writing to offchain storage"),
		metric.WithUnit("seconds"),
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

	// Heartbeat Tracking
	vm.heartbeatsSentCounter, err = beholder.GetMeter().Int64Counter(
		"verifier_heartbeats_sent_total",
		metric.WithDescription("Total number of successfully sent heartbeats"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register heartbeats sent counter: %w", err)
	}

	vm.heartbeatsFailedCounter, err = beholder.GetMeter().Int64Counter(
		"verifier_heartbeats_failed_total",
		metric.WithDescription("Total number of failed heartbeat attempts"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register heartbeats failed counter: %w", err)
	}

	vm.heartbeatDurationSeconds, err = beholder.GetMeter().Float64Histogram(
		"verifier_heartbeat_duration_seconds",
		metric.WithDescription("Duration of heartbeat requests"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register heartbeat duration histogram: %w", err)
	}

	vm.verifierHeartbeatTimestamp, err = beholder.GetMeter().Float64Gauge(
		"verifier_heartbeat_timestamp",
		metric.WithDescription("Timestamp from the heartbeat response"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register verifier heartbeat timestamp gauge: %w", err)
	}

	vm.verifierHeartbeatSentChainHeads, err = beholder.GetMeter().Int64Gauge(
		"verifier_heartbeat_sent_chain_heads",
		metric.WithDescription("Block height sent in the heartbeat request for a chain"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register verifier heartbeat sent chain heads gauge: %w", err)
	}

	vm.verifierHeartbeatChainHeads, err = beholder.GetMeter().Int64Gauge(
		"verifier_heartbeat_chain_heads",
		metric.WithDescription("Block height for a chain from the heartbeat response"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register verifier heartbeat chain heads gauge: %w", err)
	}

	vm.verifierHeartbeatScore, err = beholder.GetMeter().Float64Gauge(
		"verifier_heartbeat_score",
		metric.WithDescription("Score for a chain from the heartbeat response"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register verifier heartbeat score gauge: %w", err)
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

	vm.finalityViolated, err = beholder.GetMeter().Int64Gauge(
		"verifier_source_chain_finality_violated",
		metric.WithDescription("Specifies if source chain finality was violated"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register finality violated gauge: %w", err)
	}

	vm.remoteChainCursed, err = beholder.GetMeter().Int64Gauge(
		"verifier_remote_chain_cursed",
		metric.WithDescription("Specifies if local chain considers remote chain as cursed"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register remote chain cursed gauge: %w", err)
	}

	vm.localChainGlobalCursed, err = beholder.GetMeter().Int64Gauge(
		"verifier_local_chain_global_cursed",
		metric.WithDescription("Specifies if local chain has global curse"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register remote chain cursed gauge: %w", err)
	}

	// Reorg Tracking
	vm.reorgTrackedSeqNumsGauge, err = beholder.GetMeter().Int64Gauge(
		"verifier_reorg_tracked_seqnums",
		metric.WithDescription("Number of sequence numbers being tracked due to reorg per destination chain"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register reorg tracked seqnums gauge: %w", err)
	}

	// HTTP API Metrics
	vm.httpActiveRequestsUpDownCounter, err = beholder.GetMeter().Int64UpDownCounter(
		"verifier_http_active_requests",
		metric.WithDescription("Number of currently active HTTP requests"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register http active requests up down counter: %w", err)
	}

	vm.httpRequestCounter, err = beholder.GetMeter().Int64Counter(
		"verifier_http_requests_total",
		metric.WithDescription("Total number of HTTP requests"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register http request counter: %w", err)
	}

	vm.httpRequestDurationSeconds, err = beholder.GetMeter().Float64Histogram(
		"verifier_http_request_duration_seconds",
		metric.WithDescription("Duration of HTTP requests"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register http request duration histogram: %w", err)
	}

	// Storage Query Metrics
	vm.storageQueryDurationSeconds, err = beholder.GetMeter().Float64Histogram(
		"verifier_storage_query_duration_seconds",
		metric.WithDescription("Duration of storage query operations"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register storage query duration histogram: %w", err)
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
		// HTTP Request Duration
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "verifier_http_request_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			}},
		),
		// Storage Query Duration
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "verifier_storage_query_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			}},
		),
	}
}

var _ verifier.MetricLabeler = (*VerifierMetricLabeler)(nil)

// VerifierMetricLabeler wraps VerifierMetrics with label support.
type VerifierMetricLabeler struct {
	metrics.Labeler
	vm *VerifierMetrics
}

// NewVerifierMetricLabeler creates a new verifier metric labeler.
func NewVerifierMetricLabeler(labeler metrics.Labeler, vm *VerifierMetrics) verifier.MetricLabeler {
	return &VerifierMetricLabeler{
		Labeler: labeler,
		vm:      vm,
	}
}

func (v *VerifierMetricLabeler) With(keyValues ...string) verifier.MetricLabeler {
	return &VerifierMetricLabeler{v.Labeler.With(keyValues...), v.vm}
}

func (v *VerifierMetricLabeler) RecordMessageE2ELatency(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messageE2ELatencySeconds.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
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
	v.vm.finalityWaitDurationSeconds.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordMessageVerificationDuration(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messageVerificationDurationSeconds.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordStorageWriteDuration(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.storageWriteDurationSeconds.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
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

func (v *VerifierMetricLabeler) IncrementHeartbeatsSent(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.heartbeatsSentCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) IncrementHeartbeatsFailed(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.heartbeatsFailedCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordHeartbeatDuration(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.heartbeatDurationSeconds.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) SetVerifierHeartbeatTimestamp(ctx context.Context, timestamp int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.verifierHeartbeatTimestamp.Record(ctx, float64(timestamp), metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) SetVerifierHeartbeatSentChainHeads(ctx context.Context, blockHeight uint64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.verifierHeartbeatSentChainHeads.Record(ctx, int64(blockHeight), metric.WithAttributes(otelLabels...)) // #nosec G115 -- block heights are within int64 range
}

func (v *VerifierMetricLabeler) SetVerifierHeartbeatChainHeads(ctx context.Context, blockHeight uint64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.verifierHeartbeatChainHeads.Record(ctx, int64(blockHeight), metric.WithAttributes(otelLabels...)) // #nosec G115 -- block heights are within int64 range
}

func (v *VerifierMetricLabeler) SetVerifierHeartbeatScore(ctx context.Context, score float64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.verifierHeartbeatScore.Record(ctx, score, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordSourceChainLatestBlock(ctx context.Context, blockNum int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.sourceChainLatestBlockGauge.Record(ctx, blockNum, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordSourceChainFinalizedBlock(ctx context.Context, blockNum int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.sourceChainFinalizedBlockGauge.Record(ctx, blockNum, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordReorgTrackedSeqNums(ctx context.Context, count int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.reorgTrackedSeqNumsGauge.Record(ctx, count, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) SetVerifierFinalityViolated(ctx context.Context, selector protocol.ChainSelector, violated bool) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	otelLabels = append(otelLabels, attribute.String("sourceChainSelector", selector.String()))
	var violatedInt int64
	if violated {
		violatedInt = 1
	}
	v.vm.finalityViolated.Record(ctx, violatedInt, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) SetRemoteChainCursed(ctx context.Context, localSelector, remoteSelector protocol.ChainSelector, cursed bool) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	otelLabels = append(otelLabels, attribute.String("localSelector", localSelector.String()))
	otelLabels = append(otelLabels, attribute.String("remoteSelector", remoteSelector.String()))
	var cursedInt int64
	if cursed {
		cursedInt = 1
	}
	v.vm.remoteChainCursed.Record(ctx, cursedInt, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) SetLocalChainGlobalCursed(ctx context.Context, localSelector protocol.ChainSelector, globalCurse bool) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	otelLabels = append(otelLabels, attribute.String("localSelector", localSelector.String()))
	var cursedInt int64
	if globalCurse {
		cursedInt = 1
	}
	v.vm.localChainGlobalCursed.Record(ctx, cursedInt, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) IncrementActiveRequestsCounter(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.httpActiveRequestsUpDownCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) IncrementHTTPRequestCounter(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.httpRequestCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) DecrementActiveRequestsCounter(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.httpActiveRequestsUpDownCounter.Add(ctx, -1, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordHTTPRequestDuration(ctx context.Context, duration time.Duration, path, method string, status int) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	// Add path, method, and status as additional attributes
	attrs := append(otelLabels,
		attribute.String("path", path),
		attribute.String("method", method),
		attribute.Int("status", status),
	)
	v.vm.httpRequestDurationSeconds.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
}

func (v *VerifierMetricLabeler) RecordStorageQueryDuration(ctx context.Context, method string, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	attrs := append(otelLabels, attribute.String("method", method))
	v.vm.storageQueryDurationSeconds.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
}
