package aggregation

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sourcegraph/conc/pool"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ protocol.HealthReporter = (*CommitReportAggregator)(nil)

const maxConsecutivePanics = 3

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
	aggregationKeyChan    chan aggregationRequest
	backgroundWorkerCount int
	quorum                QuorumValidator
	l                     logger.SugaredLogger
	monitoring            common.AggregatorMonitoring
	done                  chan struct{}

	mu                sync.RWMutex
	consecutivePanics int
}

type aggregationRequest struct {
	AggregationKey model.AggregationKey
	MessageID      model.MessageID
}

// CheckAggregation enqueues a new aggregation request for the specified message ID.
func (c *CommitReportAggregator) CheckAggregation(messageID model.MessageID, aggregationKey model.AggregationKey) error {
	request := aggregationRequest{
		MessageID:      messageID,
		AggregationKey: aggregationKey,
	}
	select {
	case c.aggregationKeyChan <- request:
		c.monitoring.Metrics().IncrementPendingAggregationsChannelBuffer(context.Background(), 1)
	default:
		return common.ErrAggregationChannelFull
	}
	return nil
}

func (c *CommitReportAggregator) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, c.l)
}

func (c *CommitReportAggregator) metrics(ctx context.Context) common.AggregatorMetricLabeler {
	return scope.AugmentMetrics(ctx, c.monitoring.Metrics())
}

// shouldSkipAggregationDueToExistingQuorum checks if we should skip creating a new aggregation
// because an existing aggregated report already meets quorum requirements.
// Returns true if aggregation should be skipped, false otherwise.
func (c *CommitReportAggregator) shouldSkipAggregationDueToExistingQuorum(ctx context.Context, messageID model.MessageID) (bool, error) {
	lggr := c.logger(ctx)

	if c.aggregatedStore == nil {
		lggr.Warnw("No aggregated store available, cannot check existing aggregations")
		return false, nil
	}

	existingReport, err := c.aggregatedStore.GetCommitAggregatedReportByMessageID(ctx, messageID)
	if err != nil {
		lggr.Warnw("Failed to check for existing aggregated report", "error", err)
		return false, nil
	}

	if existingReport == nil {
		lggr.Debugw("No existing aggregated report found, proceeding with aggregation")
		return false, nil
	}

	quorumMet, err := c.quorum.CheckQuorum(ctx, existingReport)
	if err != nil {
		lggr.Warnw("Failed to check quorum for existing report", "error", err)
		return false, nil
	}

	if quorumMet {
		lggr.Infow("Skipping aggregation: existing report already meets quorum", "verificationCount", len(existingReport.Verifications))
		return true, nil
	}

	lggr.Infow("Existing report no longer meets quorum, proceeding with new aggregation", "verificationCount", len(existingReport.Verifications))
	return false, nil
}

func (c *CommitReportAggregator) checkAggregationAndSubmitComplete(ctx context.Context, request aggregationRequest) (*model.CommitAggregatedReport, error) {
	lggr := c.logger(ctx)
	lggr.Infof("Checking aggregation for message", request.MessageID, request.AggregationKey)

	shouldSkip, err := c.shouldSkipAggregationDueToExistingQuorum(ctx, request.MessageID)
	if err != nil {
		lggr.Errorw("Error checking existing quorum", "error", err)
	} else if shouldSkip {
		lggr.Infow("Skipping aggregation due to existing quorum")
		return nil, nil
	}

	verifications, err := c.storage.ListCommitVerificationByAggregationKey(ctx, request.MessageID, request.AggregationKey)
	if err != nil {
		lggr.Errorw("Failed to list verifications", "error", err)
		return nil, err
	}

	lggr.Debugw("Verifications retrieved", "count", len(verifications))

	aggregatedReport := &model.CommitAggregatedReport{
		MessageID:     request.MessageID,
		Verifications: verifications,
	}

	lggr.Debugw("Aggregated report created", "verificationCount", len(verifications))

	quorumMet, err := c.quorum.CheckQuorum(ctx, aggregatedReport)
	if err != nil {
		lggr.Errorw("Failed to check quorum", "error", err)
		return nil, err
	}

	if quorumMet {
		if err := c.sink.SubmitAggregatedReport(ctx, aggregatedReport); err != nil {
			lggr.Errorw("Failed to submit report", "error", err)
			return nil, err
		}
		timeToAggregation := aggregatedReport.CalculateTimeToAggregation(time.Now())
		lggr.Infow("Report submitted successfully", "verifications", len(verifications), "timeToAggregation", timeToAggregation)
		c.metrics(ctx).IncrementCompletedAggregations(ctx)
		c.metrics(ctx).RecordTimeToAggregation(ctx, timeToAggregation)
	} else {
		lggr.Infow("Quorum not met, not submitting report", "verifications", len(verifications))
	}

	return nil, nil
}

// StartBackground begins processing aggregation requests in the background.
func (c *CommitReportAggregator) StartBackground(ctx context.Context) {
	c.done = make(chan struct{})
	p := pool.New().WithMaxGoroutines(c.backgroundWorkerCount).WithContext(ctx)
	go func() {
		defer close(c.done)
		for {
			select {
			case request := <-c.aggregationKeyChan:
				p.Go(func(poolCtx context.Context) error {
					c.monitoring.Metrics().DecrementPendingAggregationsChannelBuffer(poolCtx, 1)
					poolCtx = scope.WithAggregationKey(poolCtx, request.AggregationKey)
					poolCtx = scope.WithMessageID(poolCtx, request.MessageID)

					var didPanic bool
					err := func() (err error) {
						defer func() {
							if r := recover(); r != nil {
								c.logger(poolCtx).Errorw("Panic during aggregation", "panic", r)
								didPanic = true
								err = fmt.Errorf("panic: %v", r)
							}
						}()
						_, err = c.checkAggregationAndSubmitComplete(poolCtx, request)
						return err
					}()

					c.mu.Lock()
					if didPanic {
						c.consecutivePanics++
						if c.consecutivePanics >= maxConsecutivePanics {
							c.logger(poolCtx).Errorw("Aggregator unhealthy: too many consecutive panics",
								"consecutivePanics", c.consecutivePanics)
						}
					} else {
						c.consecutivePanics = 0
					}
					c.mu.Unlock()

					if err != nil {
						c.logger(poolCtx).Errorw("Error checking aggregation", "error", err)
					}
					return err
				})
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *CommitReportAggregator) Ready() error {
	select {
	case <-c.done:
		return fmt.Errorf("aggregation worker stopped")
	default:
	}

	c.mu.RLock()
	consecutivePanics := c.consecutivePanics
	c.mu.RUnlock()

	if consecutivePanics >= maxConsecutivePanics {
		return fmt.Errorf("aggregator unhealthy: %d consecutive panics", consecutivePanics)
	}

	lggr := c.logger(context.Background())
	pending := len(c.aggregationKeyChan)
	capacity := cap(c.aggregationKeyChan)
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
func NewCommitReportAggregator(storage common.CommitVerificationStore, aggregatedStore common.CommitVerificationAggregatedStore, sink common.Sink, quorum QuorumValidator, config *model.AggregatorConfig, logger logger.SugaredLogger, monitoring common.AggregatorMonitoring) *CommitReportAggregator {
	return &CommitReportAggregator{
		storage:               storage,
		aggregatedStore:       aggregatedStore,
		sink:                  sink,
		aggregationKeyChan:    make(chan aggregationRequest, config.Aggregation.ChannelBufferSize),
		backgroundWorkerCount: config.Aggregation.BackgroundWorkerCount,
		quorum:                quorum,
		monitoring:            monitoring,
		l:                     logger,
	}
}
