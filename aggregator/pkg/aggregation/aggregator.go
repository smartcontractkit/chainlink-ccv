package aggregation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sourcegraph/conc/pool"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ protocol.HealthReporter = (*CommitReportAggregator)(nil)

type QuorumValidator interface {
	// CheckQuorum checks if the aggregated report meets the quorum requirements.
	CheckQuorum(ctx context.Context, report *model.CommitAggregatedReport) (bool, error)
}

// CommitReportAggregator is responsible for aggregating commit reports from multiple verifiers.
// It manages the verification and storage of commit reports through a configurable storage backend,
// processes aggregation requests via a message channel, and forwards verified reports to a sink.
type CommitReportAggregator struct {
	storage               common.CommitVerificationStore
	aggregatedStore       common.CommitVerificationAggregatedStore
	sink                  common.Sink
	channelManager        *ChannelManager
	backgroundWorkerCount int
	operationTimeout      time.Duration
	quorum                QuorumValidator
	l                     logger.SugaredLogger
	monitoring            common.AggregatorMonitoring

	mu                   sync.RWMutex
	done                 chan struct{}
	maxConsecutiveErrors uint32
	consecutiveErrors    atomic.Uint32
}

type aggregationRequest struct {
	AggregationKey model.AggregationKey
	MessageID      model.MessageID
	ChannelKey     model.ChannelKey
}

// CheckAggregation enqueues a new aggregation request for the specified message ID.
func (c *CommitReportAggregator) CheckAggregation(ctx context.Context, messageID model.MessageID, aggregationKey model.AggregationKey, channelKey model.ChannelKey, maxBlockTime time.Duration) error {
	request := aggregationRequest{
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		ChannelKey:     channelKey,
	}
	err := c.channelManager.Enqueue(ctx, channelKey, request, maxBlockTime)
	if err != nil {
		return err
	}
	c.metrics(ctx).With("channel_key", string(channelKey)).IncrementPendingAggregationsChannelBuffer(ctx, 1)
	return nil
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
		lggr.Infow("Skipping aggregation: existing report already meets quorum", "verificationCount", len(existingReport.Verifications))
		return true
	}

	lggr.Infow("Existing report no longer meets quorum, proceeding with new aggregation", "verificationCount", len(existingReport.Verifications))
	return false
}

func (c *CommitReportAggregator) checkAggregationAndSubmitComplete(ctx context.Context, request aggregationRequest) error {
	if c.operationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.operationTimeout)
		defer cancel()
	}

	lggr := c.logger(ctx)
	lggr.Info("Checking aggregation for message")

	shouldSkip := c.shouldSkipAggregationDueToExistingQuorum(ctx, request.MessageID, request.AggregationKey)
	if shouldSkip {
		return nil
	}

	verifications, err := c.storage.ListCommitVerificationByAggregationKey(ctx, request.MessageID, request.AggregationKey)
	if err != nil {
		lggr.Errorw("Failed to list verifications", "error", err)
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
		return err
	}

	if quorumMet {
		if err := c.sink.SubmitAggregatedReport(ctx, aggregatedReport); err != nil {
			lggr.Errorw("Failed to submit report", "error", err)
			return err
		}
		timeToAggregation := aggregatedReport.CalculateTimeToAggregation(time.Now())
		lggr.Infow("Report submitted successfully", "verifications", len(verifications), "timeToAggregation", timeToAggregation)
		c.metrics(ctx).IncrementCompletedAggregations(ctx)
		c.metrics(ctx).RecordTimeToAggregation(ctx, timeToAggregation)
	} else {
		lggr.Infow("Quorum not met, not submitting report", "verifications", len(verifications))
	}

	return nil
}

// StartBackground begins processing aggregation requests in the background.
func (c *CommitReportAggregator) StartBackground(ctx context.Context) {
	c.mu.Lock()
	c.done = make(chan struct{})
	go func() { _ = c.channelManager.Start(ctx) }()
	c.mu.Unlock()
	aggregationChannel := c.channelManager.AggregationChannel
	p := pool.New().WithMaxGoroutines(c.backgroundWorkerCount).WithContext(ctx)
	go func() {
		defer close(c.done)
		for {
			select {
			case request := <-aggregationChannel:
				p.Go(func(poolCtx context.Context) error {
					c.metrics(poolCtx).With("channel_key", string(request.ChannelKey)).DecrementPendingAggregationsChannelBuffer(poolCtx, 1)
					poolCtx = scope.WithAggregationKey(poolCtx, request.AggregationKey)
					poolCtx = scope.WithMessageID(poolCtx, request.MessageID)

					return func() (err error) {
						defer func() {
							if r := recover(); r != nil {
								c.logger(poolCtx).Errorw("Panic during aggregation", "panic", r)
								c.metrics(poolCtx).IncrementPanics(poolCtx)
								err = fmt.Errorf("panic: %v", r)
							}
						}()
						err = c.checkAggregationAndSubmitComplete(poolCtx, request)
						if err != nil {
							c.consecutiveErrors.Add(1)
						} else {
							c.consecutiveErrors.Store(0)
						}
						return err
					}()
				})
			case <-ctx.Done():
				return
			}
		}
	}()
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

	lggr := c.logger(context.Background())
	pending := len(c.channelManager.AggregationChannel)
	capacity := cap(c.channelManager.AggregationChannel)
	if pending >= capacity {
		lggr.Warnw("aggregation queue full", "capacity", capacity, "pending", pending)
		return nil
	}

	if float64(pending)/float64(capacity) > 0.8 {
		lggr.Warnw("aggregation queue over 80%% full", "capacity", capacity, "pending", pending)
		return nil
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
//
// Returns:
//   - *CommitReportAggregator: A new aggregator instance ready to process commit reports
//
// The returned aggregator must have StartBackground called to begin processing aggregation requests.
func NewCommitReportAggregator(storage common.CommitVerificationStore, aggregatedStore common.CommitVerificationAggregatedStore, sink common.Sink, quorum QuorumValidator, config *model.AggregatorConfig, logger logger.SugaredLogger, monitoring common.AggregatorMonitoring, channelManager *ChannelManager) *CommitReportAggregator {
	return &CommitReportAggregator{
		storage:               storage,
		aggregatedStore:       aggregatedStore,
		sink:                  sink,
		channelManager:        channelManager,
		backgroundWorkerCount: config.Aggregation.BackgroundWorkerCount,
		operationTimeout:      config.Aggregation.OperationTimeout,
		maxConsecutiveErrors:  config.Aggregation.MaxConsecutiveErrors,
		quorum:                quorum,
		monitoring:            monitoring,
		l:                     logger,
	}
}
