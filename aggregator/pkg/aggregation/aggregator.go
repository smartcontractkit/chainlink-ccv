package aggregation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sourcegraph/conc/pool"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-ccv/common/jobqueue"
	commontracing "github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ protocol.HealthReporter = (*CommitReportAggregator)(nil)

const (
	// pendingFallbackInterval bounds how late work published by another replica is picked
	// up, since signals are in-process only.
	pendingFallbackInterval = jobqueue.DefaultPendingFallbackInterval
	// staleReclaimInterval is how often locks left behind by a crashed replica are swept.
	staleReclaimInterval  = 1 * time.Minute
	cleanupInterval       = 4 * time.Hour
	retentionPeriod       = 30 * 24 * time.Hour
	queueOperationTimeout = 30 * time.Second
	retryDelay            = 30 * time.Second
)

type QuorumValidator interface {
	// CheckQuorum checks if the aggregated report meets the quorum requirements.
	CheckQuorum(ctx context.Context, report *model.CommitAggregatedReport) (bool, error)
}

// CommitReportAggregator is responsible for aggregating commit reports from multiple verifiers.
// It manages the verification and storage of commit reports through a configurable storage backend,
// processes aggregation requests via a durable job queue, and forwards verified reports to a sink.
type CommitReportAggregator struct {
	storage               common.CommitVerificationStore
	aggregatedStore       common.CommitVerificationAggregatedStore
	sink                  common.Sink
	queue                 jobqueue.JobQueue[aggregationRequest]
	backgroundWorkerCount int
	operationTimeout      time.Duration
	quorum                QuorumValidator
	committee             *model.Committee
	l                     logger.SugaredLogger
	monitoring            common.AggregatorMonitoring

	drainTimeout time.Duration

	mu                   sync.RWMutex
	done                 chan struct{}
	maxConsecutiveErrors uint32
	consecutiveErrors    atomic.Uint32
}

type aggregationRequest struct {
	AggregationKey model.AggregationKey
	MessageID      model.MessageID
	// TraceParent carries the enqueueing write span's W3C traceparent
	TraceParent string
}

// DedupKey makes aggregationRequest storable in the durable queue. Aggregation runs per
// aggregation key, which already commits to the message ID, so requests collapse per key and
// only while a job for that key is still pending.
func (r aggregationRequest) DedupKey() string {
	return r.AggregationKey
}

// CheckAggregation enqueues a new aggregation request for the specified message ID.
func (c *CommitReportAggregator) CheckAggregation(ctx context.Context, messageID model.MessageID, aggregationKey model.AggregationKey) error {
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	request := aggregationRequest{
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		TraceParent:    carrier.Get("traceparent"),
	}
	publishCtx, cancel := context.WithTimeout(ctx, queueOperationTimeout)
	defer cancel()
	return c.queue.Publish(publishCtx, request)
}

func (c *CommitReportAggregator) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, c.l)
}

func (c *CommitReportAggregator) metrics(ctx context.Context) common.AggregatorMetricLabeler {
	metrics := scope.AugmentMetrics(ctx, c.monitoring.Metrics())
	metrics = metrics.With("component", "aggregator_worker")
	return metrics
}

// shouldSkipAggregationDueToExistingQuorum checks if we should skip creating a new aggregation
// because an existing aggregated report already meets quorum requirements.
// Returns true if aggregation should be skipped, false otherwise.
func (c *CommitReportAggregator) shouldSkipAggregationDueToExistingQuorum(ctx context.Context, messageID model.MessageID, aggregationKey model.AggregationKey) bool {
	lggr := c.logger(ctx)

	if c.aggregatedStore == nil {
		lggr.Warnw("No aggregated store available, cannot check existing aggregations")
		return false
	}

	existingReport, err := c.aggregatedStore.GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey)
	if err != nil {
		if errors.Is(err, common.ErrNotFound) {
			return false
		}
		lggr.Warnw("Failed to check for existing aggregated report", "error", err)
		return false
	}

	if existingReport == nil {
		lggr.Debugw("No existing aggregated report found, proceeding with aggregation")
		return false
	}

	quorumMet, err := c.quorum.CheckQuorum(ctx, existingReport)
	if err != nil {
		lggr.Warnw("Failed to check quorum for existing report", "error", err)
		return false
	}

	if quorumMet {
		lggr.Debugw("Skipping aggregation: existing report already meets quorum", "verificationCount", len(existingReport.Verifications))
		return true
	}

	lggr.Debugw("Existing report no longer meets quorum, proceeding with new aggregation", "verificationCount", len(existingReport.Verifications))
	return false
}

func (c *CommitReportAggregator) checkAggregationAndSubmitComplete(ctx context.Context, request aggregationRequest) error {
	if c.operationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.operationTimeout)
		defer cancel()
	}

	lggr := c.logger(ctx)
	lggr.Debug("Checking aggregation for message")

	// Extract the enqueueing write-request's traceparent as ctx's active span before
	// starting our span, so StartMessageSpan uses it as a real parent - the aggregation
	// work becomes a genuine child of that write, not a same-messageID sibling.
	if request.TraceParent != "" {
		carrier := propagation.MapCarrier{"traceparent": request.TraceParent}
		ctx = otel.GetTextMapPropagator().Extract(ctx, carrier)
	}
	ctx, span := c.monitoring.Tracing().StartMessageSpan(ctx, monitoring.AggregationWorkSpanName, monitoring.MessageIDToBytes32(request.MessageID),
		commontracing.AlwaysSampled(),
		commontracing.WithAttributes(commontracing.AggregationKeyKey, request.AggregationKey),
	)
	defer span.End()

	shouldSkip := c.shouldSkipAggregationDueToExistingQuorum(ctx, request.MessageID, request.AggregationKey)
	if shouldSkip {
		span.AddEvent(monitoring.EventAggregationSkipped)
		return nil
	}

	verifications, err := c.storage.ListCommitVerificationByAggregationKey(ctx, request.MessageID, request.AggregationKey)
	if err != nil {
		lggr.Errorw("Failed to list verifications", "error", err)
		span.RecordError(err)
		return err
	}

	lggr.Debugw("Verifications retrieved", "count", len(verifications))

	aggregatedReport := &model.CommitAggregatedReport{
		MessageID:      request.MessageID,
		AggregationKey: request.AggregationKey,
		Verifications:  verifications,
	}

	lggr.Debugw("Aggregated report created", "verificationCount", len(verifications))

	quorumMet, err := c.quorum.CheckQuorum(ctx, aggregatedReport)
	if err != nil {
		lggr.Errorw("Failed to check quorum", "error", err)
		span.RecordError(err)
		return err
	}
	span.SetAttributes(attribute.Bool(commontracing.QuorumMetKey, quorumMet))

	if !quorumMet {
		span.AddEvent(monitoring.EventQuorumNotMet)
		lggr.Debugw("Quorum not met, not submitting report", "verifications", len(verifications))
		return nil
	}

	return c.submitAggregatedReport(ctx, lggr, span, request, aggregatedReport, verifications)
}

// submitAggregatedReport maps and submits a report that has met quorum, recording the
// outcome (unexportable, already submitted by a concurrent worker, or submitted) on span.
func (c *CommitReportAggregator) submitAggregatedReport(ctx context.Context, lggr logger.SugaredLogger, span oteltrace.Span, request aggregationRequest, aggregatedReport *model.CommitAggregatedReport, verifications []*model.CommitVerificationRecord) error {
	if c.committee == nil {
		lggr.Errorw("Cannot map aggregated report for export: committee configuration is missing")
		span.AddEvent(monitoring.EventReportUnexportable)
		c.metrics(ctx).IncrementAggregationsBlockedUnexportable(ctx)
		return nil
	}
	if _, err := model.MapAggregatedReportToVerifierResultProto(aggregatedReport, c.committee); err != nil {
		lggr.Errorw("Aggregated report is not exportable", "error", err)
		span.AddEvent(monitoring.EventReportUnexportable)
		c.metrics(ctx).IncrementAggregationsBlockedUnexportable(ctx)
		return nil
	}
	inserted, err := c.sink.SubmitAggregatedReport(ctx, aggregatedReport)
	if err != nil {
		lggr.Errorw("Failed to submit report", "error", err)
		span.RecordError(err)
		return err
	}
	if !inserted {
		// A concurrent worker for the same message/aggregation key already inserted the
		// identical report first (see SubmitAggregatedReport's ON CONFLICT DO NOTHING) -
		// not an error, just this worker losing the race.
		span.AddEvent(monitoring.EventAggregationAlreadySubmitted)
		lggr.Debugw("Aggregated report already submitted by a concurrent worker", "verifications", len(verifications))
		return nil
	}
	span.AddEvent(monitoring.EventReportSubmitted)
	timeToAggregation := aggregatedReport.CalculateTimeToAggregation(time.Now())
	// PER-MESSAGE LOG (success): one line per message, on quorum.
	lggr.Infow("Report submitted successfully", protocol.LogTypeKey, protocol.LogTypeMessageSuccess, protocol.LogKeyMessageID, protocol.ByteSlice(request.MessageID).String(), "verifications", len(verifications), "timeToAggregation", timeToAggregation)
	c.metrics(ctx).IncrementCompletedAggregations(ctx)
	c.metrics(ctx).RecordTimeToAggregation(ctx, timeToAggregation)
	return nil
}

// StartBackground begins consuming aggregation requests from the durable queue in the
// background.
func (c *CommitReportAggregator) StartBackground(ctx context.Context) {
	c.mu.Lock()
	c.done = make(chan struct{})
	c.mu.Unlock()

	poolCtx, poolCancel := context.WithCancel(context.WithoutCancel(ctx))
	p := pool.New().WithMaxGoroutines(c.backgroundWorkerCount).WithContext(poolCtx)

	drainDeadline := make(chan struct{})
	go func() {
		<-ctx.Done()
		time.Sleep(c.drainTimeout)
		close(drainDeadline)
	}()

	go func() { //nolint:gosec // G118: long-lived drain goroutine outlives the request ctx by design
		defer close(c.done)
		defer poolCancel()
		lggr := c.logger(context.Background())

		signals := c.queue.Signals()
		pendingTicker := time.NewTicker(pendingFallbackInterval)
		defer pendingTicker.Stop()
		staleTicker := time.NewTicker(staleReclaimInterval)
		defer staleTicker.Stop()
		cleanupTicker := time.NewTicker(cleanupInterval)
		defer cleanupTicker.Stop()

		// Both rearms are primed: work published before this process started, or published
		// by another replica, has no in-process signal to announce it.
		pendingRearm := make(chan struct{}, 1)
		pendingRearm <- struct{}{}
		staleRearm := make(chan struct{}, 1)
		staleRearm <- struct{}{}

		for {
			select {
			case <-ctx.Done():
				c.waitForPool(lggr, p, drainDeadline, poolCancel)
				return
			case <-drainDeadline:
				lggr.Errorw("Drain timed out, dropping in-flight work", "timeout", c.drainTimeout)
				poolCancel()
				_ = p.Wait()
				return

			case <-signals:
				c.consumeBatch(ctx, p, pendingRearm, c.queue.ConsumePending, "Failed to consume pending aggregation jobs")
			case <-pendingRearm:
				c.consumeBatch(ctx, p, pendingRearm, c.queue.ConsumePending, "Failed to consume pending aggregation jobs")
			case <-pendingTicker.C:
				c.consumeBatch(ctx, p, pendingRearm, c.queue.ConsumePending, "Failed to consume pending aggregation jobs")

			case <-staleRearm:
				c.consumeBatch(ctx, p, staleRearm, c.queue.ReclaimStale, "Failed to reclaim stale aggregation jobs")
			case <-staleTicker.C:
				c.consumeBatch(ctx, p, staleRearm, c.queue.ReclaimStale, "Failed to reclaim stale aggregation jobs")

			case <-cleanupTicker.C:
				c.cleanup(ctx, lggr)
			}
		}
	}()
}

// consumeBatch locks one batch of jobs and dispatches each into the worker pool. It
// re-arms when the batch came back full, because signals coalesce and a single wakeup can
// stand for any amount of work.
func (c *CommitReportAggregator) consumeBatch(
	ctx context.Context,
	p *pool.ContextPool,
	rearm chan<- struct{},
	consume func(context.Context, int) ([]jobqueue.Job[aggregationRequest], error),
	consumeErrMsg string,
) {
	// A claim is capped at the worker count; surplus would sit unstarted in 'processing'
	// until reclaimed as stale.
	batchSize := c.backgroundWorkerCount
	consumeCtx, cancel := context.WithTimeout(ctx, queueOperationTimeout)
	jobs, err := consume(consumeCtx, batchSize)
	cancel()
	if err != nil {
		c.logger(ctx).Errorw(consumeErrMsg, "error", err)
		return
	}
	if len(jobs) == 0 {
		return
	}
	if len(jobs) == batchSize {
		select {
		case rearm <- struct{}{}:
		default:
		}
	}
	for _, job := range jobs {
		c.submitWork(p, job)
	}
}

func (c *CommitReportAggregator) submitWork(p *pool.ContextPool, job jobqueue.Job[aggregationRequest]) {
	p.Go(func(poolCtx context.Context) error {
		request := job.Payload
		poolCtx = scope.WithAggregationKey(poolCtx, request.AggregationKey)
		poolCtx = scope.WithMessageID(poolCtx, request.MessageID)

		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					c.logger(poolCtx).Errorw("Panic during aggregation", "panic", r)
					c.metrics(poolCtx).IncrementPanics(poolCtx)
					err = fmt.Errorf("panic: %v", r)
				}
			}()
			return c.checkAggregationAndSubmitComplete(poolCtx, request)
		}()

		opCtx, cancel := context.WithTimeout(context.WithoutCancel(poolCtx), queueOperationTimeout)
		defer cancel()
		if err != nil {
			c.consecutiveErrors.Add(1)
			if retryErr := c.queue.Retry(opCtx, retryDelay, map[string]error{job.ID: err}, job.ID); retryErr != nil {
				c.logger(poolCtx).Errorw("Failed to schedule aggregation retry, job will be reclaimed as a stale lock", "error", retryErr)
			}
			return err
		}
		c.consecutiveErrors.Store(0)
		if completeErr := c.queue.Complete(opCtx, job.ID); completeErr != nil {
			c.logger(poolCtx).Errorw("Failed to complete aggregation job, job will be reclaimed as a stale lock", "error", completeErr)
		}
		return nil
	})
}

func (c *CommitReportAggregator) cleanup(ctx context.Context, lggr logger.SugaredLogger) {
	cleanupCtx, cancel := context.WithTimeout(ctx, queueOperationTimeout)
	defer cancel()
	deleted, err := c.queue.Cleanup(cleanupCtx, retentionPeriod)
	if err != nil {
		lggr.Errorw("Failed to clean up aggregation job archive", "error", err)
		return
	}
	if deleted > 0 {
		lggr.Infow("Cleaned up archived aggregation jobs", "count", deleted, "retentionPeriod", retentionPeriod)
	}
}

func (c *CommitReportAggregator) waitForPool(lggr logger.SugaredLogger, p *pool.ContextPool, drainDeadline <-chan struct{}, poolCancel context.CancelFunc) {
	lggr.Infow("Stopped consuming, waiting for in-flight workers")
	poolDone := make(chan error, 1)
	go func() { poolDone <- p.Wait() }()
	select {
	case poolErr := <-poolDone:
		if poolErr != nil {
			lggr.Errorw("Pool workers returned errors during shutdown", "error", poolErr)
		} else {
			lggr.Infow("Aggregation worker shutdown completed cleanly")
		}
	case <-drainDeadline:
		lggr.Errorw("Drain timed out waiting for in-flight workers", "timeout", c.drainTimeout)
		poolCancel()
		if poolErr := <-poolDone; poolErr != nil {
			lggr.Errorw("Pool workers returned errors after forced cancellation", "error", poolErr)
		}
	}
}

func (c *CommitReportAggregator) Ready() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.done == nil {
		return fmt.Errorf("aggregation worker not started")
	}

	select {
	case <-c.done:
		return fmt.Errorf("aggregation worker stopped")
	default:
	}

	if c.maxConsecutiveErrors != 0 {
		if c.consecutiveErrors.Load() >= c.maxConsecutiveErrors {
			return fmt.Errorf("aggregation worker failed %d times in a row", c.consecutiveErrors.Load())
		}
	}

	return nil
}

func (c *CommitReportAggregator) HealthReport() map[string]error {
	return map[string]error{
		c.Name(): c.Ready(),
	}
}

func (c *CommitReportAggregator) Name() string {
	return "aggregation_service"
}

// NewCommitReportAggregator creates a new instance of CommitReportAggregator with the provided dependencies.
// It initializes the aggregator with a storage backend for commit verifications, a sink for forwarding
// completed reports, and configuration settings for committee quorum requirements.
//
// Parameters:
//   - storage: Interface for storing and retrieving commit verifications
//   - aggregatedStore: Interface for querying existing aggregated reports (can be nil to disable the feature)
//   - sink: Interface for submitting aggregated reports
//   - config: Configuration containing committee and quorum settings
//   - queue: Durable queue carrying aggregation requests between replicas
//
// Returns:
//   - *CommitReportAggregator: A new aggregator instance ready to process commit reports
//
// The returned aggregator must have StartBackground called to begin processing aggregation requests.
func NewCommitReportAggregator(storage common.CommitVerificationStore, aggregatedStore common.CommitVerificationAggregatedStore, sink common.Sink, quorum QuorumValidator, config *model.AggregatorConfig, logger logger.SugaredLogger, monitoring common.AggregatorMonitoring, queue jobqueue.JobQueue[aggregationRequest]) *CommitReportAggregator {
	return &CommitReportAggregator{
		storage:               storage,
		aggregatedStore:       aggregatedStore,
		sink:                  sink,
		queue:                 queue,
		backgroundWorkerCount: config.Aggregation.BackgroundWorkerCount,
		operationTimeout:      config.Aggregation.OperationTimeout,
		drainTimeout:          config.Aggregation.DrainTimeout,
		maxConsecutiveErrors:  config.Aggregation.MaxConsecutiveErrors,
		quorum:                quorum,
		committee:             config.Committee,
		monitoring:            monitoring,
		l:                     logger,
	}
}
