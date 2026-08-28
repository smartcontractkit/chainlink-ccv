package monitoring

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

const (
	MessageTransitionStageSourceRead      = "source_read"
	MessageTransitionStagePendingFinality = "pending_finality"
	MessageTransitionStageAdmission       = "admission"
	MessageTransitionStagePolicy          = "policy"
	MessageTransitionStageVerification    = "verification"
	MessageTransitionStageStorageWrite    = "storage_write"

	MessageTransitionOutcomeDiscovered        = "discovered"
	MessageTransitionOutcomeFiltered          = "filtered"
	MessageTransitionOutcomeMessageIDMismatch = "message_id_mismatch"
	MessageTransitionOutcomeQueued            = "queued"
	MessageTransitionOutcomeFinalityBlocked   = "finality_blocked"
	MessageTransitionOutcomePublished         = "published"
	MessageTransitionOutcomeLaneCursed        = "lane_cursed"
	MessageTransitionOutcomeCurseStateUnknown = "curse_state_unknown"
	MessageTransitionOutcomeMessageDisabled   = "message_disabled"
	MessageTransitionOutcomeRulesStateUnknown = "rules_state_unknown"
	MessageTransitionOutcomeQueuePublishError = "queue_publish_error"
	MessageTransitionOutcomePolicyPassed      = "policy_passed"
	MessageTransitionOutcomePolicyRejected    = "policy_rejected"
	MessageTransitionOutcomePolicyUnavailable = "policy_unavailable"
	MessageTransitionOutcomePolicySkipped     = "policy_skipped"
	MessageTransitionOutcomeSucceeded         = "succeeded"
	MessageTransitionOutcomeRetryScheduled    = "retry_scheduled"
	MessageTransitionOutcomePermanentlyFailed = "permanently_failed"

	MessageTransitionReasonNone                   = "none"
	MessageTransitionReasonFilter                 = "filter"
	MessageTransitionReasonMessageIDComputeFailed = "message_id_compute_failed"
	MessageTransitionReasonMessageIDMismatch      = "message_id_mismatch"
	MessageTransitionReasonFinalityViolation      = "finality_violation"
	MessageTransitionReasonRemoteChainCursed      = "remote_chain_cursed"
	MessageTransitionReasonCurseStateUnknown      = "curse_state_unknown"
	MessageTransitionReasonMessageDisablementRule = "message_disablement_rule"
	MessageTransitionReasonRulesStateUnknown      = "rules_state_unknown"
	MessageTransitionReasonPolicyRejected         = "policy_rejected"
	MessageTransitionReasonPolicyEndpointError    = "policy_endpoint_error"
	MessageTransitionReasonTaskInvalid            = "task_invalid"
	MessageTransitionReasonQueuePublishFailed     = "queue_publish_failed"
	MessageTransitionReasonVerificationFailed     = "verification_failed"
	MessageTransitionReasonStorageWriteFailed     = "storage_write_failed"
	MessageTransitionReasonBatchWriteFailed       = "batch_write_failed"

	MessageInFlightStatePendingFinality = "pending_finality"

	SourceReaderStateRunning         = "running"
	SourceReaderStateDisabled        = "disabled"
	SourceReaderStateFinalityBlocked = "finality_blocked"
	SourceReaderStatePollError       = "poll_error"

	MessageFailureClassUnknown                     = "unknown"
	MessageFailureClassUnsupportedMessageVersion   = "unsupported_message_version"
	MessageFailureClassSourceChainNotConfigured    = "source_chain_not_configured"
	MessageFailureClassMissingReceiptBlob          = "missing_receipt_blob"
	MessageFailureClassMissingVerifierExecutorBlob = "missing_verifier_or_executor_blob"
	MessageFailureClassSigningFailed               = "signing_failed"
	MessageFailureClassAttestationNotReady         = "attestation_not_ready"
	MessageFailureClassAttestationFetchFailed      = "attestation_fetch_failed"
	MessageFailureClassAttestationDecodeFailed     = "attestation_decode_failed"
	MessageFailureClassAggregatorDeadlineExceeded  = "aggregator_deadline_exceeded"
	MessageFailureClassAggregatorResourceExhausted = "aggregator_resource_exhausted"
	MessageFailureClassAggregatorPayloadTooLarge   = "aggregator_payload_too_large"
	MessageFailureClassAggregatorUnavailable       = "aggregator_unavailable"
	MessageFailureClassPolicyRejected              = "policy_rejected"
	MessageFailureClassPolicyEndpointError         = "policy_endpoint_error"
)

// VerifierMetrics provides all metrics for the verifier.
type VerifierMetrics struct {
	// E2E Latency - North Star Metric
	messageE2ELatencySeconds metric.Float64Histogram

	// Message Processing Counters
	messagesProcessedCounter   metric.Int64Counter
	messagesVerificationFailed metric.Int64Counter
	messageTransitions         metric.Int64Counter
	messageFailures            metric.Int64Counter
	messagesInFlight           metric.Int64Gauge
	oldestMessageAgeSeconds    metric.Float64Gauge

	// Fine-Grained Latency Breakdown
	taskVerificationDurationSeconds metric.Float64Histogram
	storageWriteDurationSeconds     metric.Float64Histogram
	verificationQueueLatencySeconds metric.Float64Histogram

	// Queue Health
	taskVerificationQueueSizeGauge metric.Int64Gauge
	storageWriteQueueSizeGauge     metric.Int64Gauge

	// Error Tracking
	taskVerificationPermanentErrors metric.Int64Counter
	storageWriteErrorsCounter       metric.Int64Counter

	criticalSourceInvariantViolations metric.Int64Counter

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
	sourceChainSafeBlockGauge      metric.Int64Gauge
	finalityViolated               metric.Int64Gauge
	remoteChainCursed              metric.Int64Gauge
	localChainGlobalCursed         metric.Int64Gauge

	messageDisablementRulesRefreshFailure metric.Int64Gauge

	// Reorg/Finality  Tracking
	reorgTrackedSeqNumsGauge                metric.Int64Gauge
	sourceReaderLastSuccessfulPollTimestamp metric.Float64Gauge
	sourceReaderLastProcessedFinalizedBlock metric.Int64Gauge
	sourceReaderState                       metric.Int64Gauge

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
		"verifier_messages_verification_total",
		metric.WithDescription("Total number of successfully processed and stored messages"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register messages processed counter: %w", err)
	}

	vm.messagesVerificationFailed, err = beholder.GetMeter().Int64Counter(
		"verifier_messages_verification_errors",
		metric.WithDescription("Total number of messages that failed verification"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register messages verification failed counter: %w", err)
	}
	vm.messageTransitions, err = beholder.GetMeter().Int64Counter("verifier_message_transitions_total", metric.WithDescription("Message pipeline transitions by stage and outcome"))
	if err != nil {
		return nil, fmt.Errorf("failed to register message transitions counter: %w", err)
	}
	vm.messageFailures, err = beholder.GetMeter().Int64Counter("verifier_message_failures_total", metric.WithDescription("Message failures by stage, retryability, and classified cause"))
	if err != nil {
		return nil, fmt.Errorf("failed to register message failures counter: %w", err)
	}
	vm.messagesInFlight, err = beholder.GetMeter().Int64Gauge("verifier_messages_in_flight", metric.WithDescription("Current in-flight messages by pipeline state"))
	if err != nil {
		return nil, fmt.Errorf("failed to register messages in flight gauge: %w", err)
	}
	vm.oldestMessageAgeSeconds, err = beholder.GetMeter().Float64Gauge("verifier_oldest_message_age_seconds", metric.WithDescription("Age of the oldest in-flight message by pipeline state"), metric.WithUnit("seconds"))
	if err != nil {
		return nil, fmt.Errorf("failed to register oldest message age gauge: %w", err)
	}

	// Fine-Grained Latency Breakdown
	vm.taskVerificationDurationSeconds, err = beholder.GetMeter().Float64Histogram(
		"verifier_task_verification_duration_seconds",
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

	vm.verificationQueueLatencySeconds, err = beholder.GetMeter().Float64Histogram(
		"verifier_verification_queue_latency_seconds",
		metric.WithDescription("Time a message spent in the verification queue from push to poll"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register verification queue latency histogram: %w", err)
	}

	// Queue Health
	vm.taskVerificationQueueSizeGauge, err = beholder.GetMeter().Int64Gauge(
		"verifier_task_verification_queue_size",
		metric.WithDescription("Current size of the task verification queue (pending + processing jobs)"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register task verification queue size gauge: %w", err)
	}

	vm.storageWriteQueueSizeGauge, err = beholder.GetMeter().Int64Gauge(
		"verifier_storage_write_queue_size",
		metric.WithDescription("Current size of the storage write queue (pending + processing jobs)"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register storage write queue size gauge: %w", err)
	}

	// Error Tracking
	vm.storageWriteErrorsCounter, err = beholder.GetMeter().Int64Counter(
		"verifier_storage_write_errors",
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

	vm.sourceChainSafeBlockGauge, err = beholder.GetMeter().Int64Gauge(
		"verifier_source_chain_safe_block",
		metric.WithDescription("Latest safe block number for a source chain"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register source chain safe block gauge: %w", err)
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

	vm.messageDisablementRulesRefreshFailure, err = beholder.GetMeter().Int64Gauge(
		"verifier_message_disablement_rules_refresh_failure",
		metric.WithDescription("Whether the latest message disablement rules refresh failed (1) or succeeded (0)"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register message disablement rules refresh failure gauge: %w", err)
	}

	// Reorg Tracking
	vm.reorgTrackedSeqNumsGauge, err = beholder.GetMeter().Int64Gauge(
		"verifier_reorg_tracked_seqnums",
		metric.WithDescription("Number of sequence numbers being tracked due to reorg per destination chain"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register reorg tracked seqnums gauge: %w", err)
	}
	vm.sourceReaderLastSuccessfulPollTimestamp, err = beholder.GetMeter().Float64Gauge("verifier_source_reader_last_successful_poll_timestamp", metric.WithDescription("Unix timestamp of the last successful source reader poll"))
	if err != nil {
		return nil, fmt.Errorf("failed to register source reader poll timestamp gauge: %w", err)
	}
	vm.sourceReaderLastProcessedFinalizedBlock, err = beholder.GetMeter().Int64Gauge("verifier_source_reader_last_processed_finalized_block", metric.WithDescription("Last finalized block processed by the source reader"))
	if err != nil {
		return nil, fmt.Errorf("failed to register source reader processed block gauge: %w", err)
	}
	vm.sourceReaderState, err = beholder.GetMeter().Int64Gauge("verifier_source_reader_state", metric.WithDescription("One-hot source reader state"))
	if err != nil {
		return nil, fmt.Errorf("failed to register source reader state gauge: %w", err)
	}

	vm.taskVerificationPermanentErrors, err = beholder.GetMeter().Int64Counter(
		"verifier_task_verification_permanent_errors_total",
		metric.WithDescription("Total number of non-retryable errors during task verification"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register task verification permanent errors counter: %w", err)
	}

	vm.criticalSourceInvariantViolations, err = beholder.GetMeter().Int64Counter(
		"verifier_critical_source_invariant_violations_total",
		metric.WithDescription("Encoded CCIP message disagrees with configured source chain observation (e.g. onRamp address or message id vs log)"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register critical source invariant violations counter: %w", err)
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

func (v *VerifierMetricLabeler) IncrementMessageTransition(ctx context.Context, stage, outcome, reason string) {
	attrs := append(beholder.OtelAttributes(v.Labels).AsStringAttributes(), attribute.String("stage", stage), attribute.String("outcome", outcome), attribute.String("reason", reason))
	v.vm.messageTransitions.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func (v *VerifierMetricLabeler) IncrementMessageFailure(ctx context.Context, stage string, retryable bool, errorClass string) {
	attrs := append(beholder.OtelAttributes(v.Labels).AsStringAttributes(), attribute.String("stage", stage), attribute.Bool("retryable", retryable), attribute.String("error_class", errorClass))
	v.vm.messageFailures.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func (v *VerifierMetricLabeler) RecordMessagesInFlight(ctx context.Context, state string, count int64) {
	attrs := append(beholder.OtelAttributes(v.Labels).AsStringAttributes(), attribute.String("state", state))
	v.vm.messagesInFlight.Record(ctx, count, metric.WithAttributes(attrs...))
}

func (v *VerifierMetricLabeler) RecordOldestMessageAge(ctx context.Context, state string, age time.Duration) {
	attrs := append(beholder.OtelAttributes(v.Labels).AsStringAttributes(), attribute.String("state", state))
	v.vm.oldestMessageAgeSeconds.Record(ctx, age.Seconds(), metric.WithAttributes(attrs...))
}

func (v *VerifierMetricLabeler) RecordMessageVerificationDuration(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.taskVerificationDurationSeconds.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordStorageWriteDuration(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.storageWriteDurationSeconds.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordVerificationQueueLatency(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.verificationQueueLatencySeconds.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordTaskVerificationQueueSize(ctx context.Context, size int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.taskVerificationQueueSizeGauge.Record(ctx, size, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordStorageWriteQueueSize(ctx context.Context, size int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.storageWriteQueueSizeGauge.Record(ctx, size, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) IncrementStorageWriteErrors(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.storageWriteErrorsCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) IncrementTaskVerificationPermanentErrors(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.taskVerificationPermanentErrors.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) IncrementCriticalSourceInvariantViolations(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.criticalSourceInvariantViolations.Add(ctx, 1, metric.WithAttributes(otelLabels...))
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

func (v *VerifierMetricLabeler) RecordSourceChainSafeBlock(ctx context.Context, blockNum int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.sourceChainSafeBlockGauge.Record(ctx, blockNum, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) RecordReorgTrackedSeqNums(ctx context.Context, count int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.reorgTrackedSeqNumsGauge.Record(ctx, count, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) SetSourceReaderState(ctx context.Context, state string) {
	attrs := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	for _, knownState := range []string{SourceReaderStateRunning, SourceReaderStateDisabled, SourceReaderStateFinalityBlocked, SourceReaderStatePollError} {
		value := int64(0)
		if knownState == state {
			value = 1
		}
		v.vm.sourceReaderState.Record(ctx, value, metric.WithAttributes(append(attrs, attribute.String("state", knownState))...))
	}
}

func (v *VerifierMetricLabeler) SetSourceReaderLastSuccessfulPollTimestamp(ctx context.Context, timestamp int64) {
	v.vm.sourceReaderLastSuccessfulPollTimestamp.Record(ctx, float64(timestamp), metric.WithAttributes(beholder.OtelAttributes(v.Labels).AsStringAttributes()...))
}

func (v *VerifierMetricLabeler) SetSourceReaderLastProcessedFinalizedBlock(ctx context.Context, blockNum int64) {
	v.vm.sourceReaderLastProcessedFinalizedBlock.Record(ctx, blockNum, metric.WithAttributes(beholder.OtelAttributes(v.Labels).AsStringAttributes()...))
}

// ClassifyError maps known operational failures to a bounded Prometheus label value.
func ClassifyError(err error) string {
	if err == nil {
		return MessageFailureClassUnknown
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "policy hook rejected"):
		return MessageFailureClassPolicyRejected
	case strings.Contains(message, "policy endpoint") || strings.Contains(message, "policy response") || strings.Contains(message, "policy request"):
		return MessageFailureClassPolicyEndpointError
	case strings.Contains(message, "unsupported message version"):
		return MessageFailureClassUnsupportedMessageVersion
	case strings.Contains(message, "source chain selector") && strings.Contains(message, "not configured"):
		return MessageFailureClassSourceChainNotConfigured
	case strings.Contains(message, "receipt blobs list is empty"):
		return MessageFailureClassMissingReceiptBlob
	case strings.Contains(message, "neither verifier nor default executor blob found"):
		return MessageFailureClassMissingVerifierExecutorBlob
	case strings.Contains(message, "failed to sign message"):
		return MessageFailureClassSigningFailed
	case strings.Contains(message, "attestation not ready") || strings.Contains(message, "attestation not found"):
		return MessageFailureClassAttestationNotReady
	case strings.Contains(message, "fetch attestation"):
		return MessageFailureClassAttestationFetchFailed
	case strings.Contains(message, "decode attestation"):
		return MessageFailureClassAttestationDecodeFailed
	case strings.Contains(message, "deadline exceeded"):
		return MessageFailureClassAggregatorDeadlineExceeded
	case strings.Contains(message, "resource exhausted") || strings.Contains(message, "queue full"):
		return MessageFailureClassAggregatorResourceExhausted
	case strings.Contains(message, "message size"):
		return MessageFailureClassAggregatorPayloadTooLarge
	case strings.Contains(message, "unavailable") || strings.Contains(message, "connection"):
		return MessageFailureClassAggregatorUnavailable
	}
	return MessageFailureClassUnknown
}

func (v *VerifierMetricLabeler) SetVerifierFinalityViolated(ctx context.Context, selector protocol.ChainSelector, violated bool) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	otelLabels = append(otelLabels,
		attribute.String("sourceChainSelector", selector.String()),
		attribute.String("sourceChainName", selector.ChainName()),
	)
	var violatedInt int64
	if violated {
		violatedInt = 1
	}
	v.vm.finalityViolated.Record(ctx, violatedInt, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) SetRemoteChainCursed(ctx context.Context, localSelector, remoteSelector protocol.ChainSelector, cursed bool) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	otelLabels = append(otelLabels,
		attribute.String("localSelector", localSelector.String()),
		attribute.String("localChainName", localSelector.ChainName()),
		attribute.String("remoteSelector", remoteSelector.String()),
		attribute.String("remoteChainName", remoteSelector.ChainName()),
	)
	var cursedInt int64
	if cursed {
		cursedInt = 1
	}
	v.vm.remoteChainCursed.Record(ctx, cursedInt, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) SetLocalChainGlobalCursed(ctx context.Context, localSelector protocol.ChainSelector, globalCurse bool) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	otelLabels = append(otelLabels,
		attribute.String("localSelector", localSelector.String()),
		attribute.String("localChainName", localSelector.ChainName()),
	)
	var cursedInt int64
	if globalCurse {
		cursedInt = 1
	}
	v.vm.localChainGlobalCursed.Record(ctx, cursedInt, metric.WithAttributes(otelLabels...))
}

func (v *VerifierMetricLabeler) SetMessageDisablementRulesRefreshFailure(ctx context.Context, failed int64) {
	otelLabels := beholder.OtelAttributes(v.Labels).AsStringAttributes()
	v.vm.messageDisablementRulesRefreshFailure.Record(ctx, failed, metric.WithAttributes(otelLabels...))
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
