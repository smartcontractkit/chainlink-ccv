package aggregation

import (
	"context"
	"time"

	"github.com/sourcegraph/conc/pool"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type QuorumValidator interface {
	// CheckQuorum checks if the aggregated report meets the quorum requirements.
	CheckQuorum(ctx context.Context, report *model.CommitAggregatedReport) (bool, error)
}

// CommitReportAggregator is responsible for aggregating commit reports from multiple verifiers.
// It manages the verification and storage of commit reports through a configurable storage backend,
// processes aggregation requests via a message channel, and forwards verified reports to a sink.
type CommitReportAggregator struct {
	storage               common.CommitVerificationStore
	sink                  common.Sink
	messageIDChan         chan aggregationRequest
	backgroundWorkerCount int
	quorum                QuorumValidator
	l                     logger.SugaredLogger
	monitoring            common.AggregatorMonitoring
	done                  chan struct{}
}

type aggregationRequest struct {
	// CommitteeID is the ID of the committee for the aggregation request.
	CommitteeID model.CommitteeID
	MessageID   model.MessageID
}

func (c *CommitReportAggregator) HealthCheck(ctx context.Context) *common.ComponentHealth {
	result := &common.ComponentHealth{
		Name:      "aggregation_service",
		Timestamp: time.Now(),
	}

	select {
	case <-c.done:
		result.Status = common.HealthStatusUnhealthy
		result.Message = "aggregation worker stopped"
		return result
	default:
	}

	pending := len(c.messageIDChan)
	capacity := cap(c.messageIDChan)

	if pending >= capacity {
		result.Status = common.HealthStatusDegraded
		result.Message = "aggregation queue full"
		return result
	}

	if float64(pending)/float64(capacity) > 0.8 {
		result.Status = common.HealthStatusDegraded
		result.Message = "aggregation queue high"
		return result
	}

	result.Status = common.HealthStatusHealthy
	result.Message = "aggregation queue healthy"
	return result
}

// CheckAggregation enqueues a new aggregation request for the specified message ID.
func (c *CommitReportAggregator) CheckAggregation(messageID model.MessageID, committeeID model.CommitteeID) error {
	request := aggregationRequest{
		MessageID:   messageID,
		CommitteeID: committeeID,
	}
	select {
	case c.messageIDChan <- request:
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

func deduplicateVerificationsByParticipant(verifications []*model.CommitVerificationRecord) []*model.CommitVerificationRecord {
	if len(verifications) <= 1 {
		return verifications
	}

	// Map from participant address (hex string) to the verification record
	participantMap := make(map[string]*model.CommitVerificationRecord)

	for _, verification := range verifications {
		if verification.IdentifierSigner == nil || len(verification.IdentifierSigner.ParticipantID) == 0 {
			continue
		}

		participantID := verification.IdentifierSigner.ParticipantID
		existing, exists := participantMap[participantID]

		if !exists || verification.GetTimestamp() > existing.GetTimestamp() {
			participantMap[participantID] = verification
		}
	}

	result := make([]*model.CommitVerificationRecord, 0, len(participantMap))
	for _, verification := range participantMap {
		result = append(result, verification)
	}

	return result
}

func (c *CommitReportAggregator) checkAggregationAndSubmitComplete(ctx context.Context, messageID model.MessageID, committeeID model.CommitteeID) (*model.CommitAggregatedReport, error) {
	lggr := c.logger(ctx)
	lggr.Infof("Checking aggregation for message", messageID, committeeID)
	verifications, err := c.storage.ListCommitVerificationByMessageID(ctx, messageID, committeeID)
	if err != nil {
		lggr.Errorw("Failed to list verifications", "error", err)
		return nil, err
	}

	lggr.Debugw("Verifications retrieved", "count", len(verifications))

	dedupedVerifications := deduplicateVerificationsByParticipant(verifications)
	if len(dedupedVerifications) < len(verifications) {
		lggr.Infow("Deduplicated verifications", "original", len(verifications), "deduplicated", len(dedupedVerifications))
	}

	aggregatedReport := &model.CommitAggregatedReport{
		MessageID:     messageID,
		CommitteeID:   committeeID,
		Verifications: dedupedVerifications,
	}

	mostRecentTimestamp := aggregatedReport.GetMostRecentVerificationTimestamp()

	lggr.Debugw("Aggregated report created", "timestamp", mostRecentTimestamp, "verificationCount", len(dedupedVerifications))

	quorumMet, err := c.quorum.CheckQuorum(ctx, aggregatedReport)
	if err != nil {
		lggr.Errorw("Failed to check quorum", "error", err)
		return nil, err
	}

	if quorumMet {
		if err := c.sink.SubmitReport(ctx, aggregatedReport); err != nil {
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
		for {
			select {
			case request := <-c.messageIDChan:
				p.Go(func(poolCtx context.Context) error {
					c.monitoring.Metrics().DecrementPendingAggregationsChannelBuffer(poolCtx, 1)
					poolCtx = scope.WithMessageID(poolCtx, request.MessageID)
					poolCtx = scope.WithCommitteeID(poolCtx, request.CommitteeID)
					_, err := c.checkAggregationAndSubmitComplete(poolCtx, request.MessageID, request.CommitteeID)
					return err
				})
			case <-ctx.Done():
				close(c.done)
				return
			}
		}
	}()
}

// NewCommitReportAggregator creates a new instance of CommitReportAggregator with the provided dependencies.
// It initializes the aggregator with a storage backend for commit verifications, a sink for forwarding
// completed reports, and configuration settings for committee quorum requirements.
//
// Parameters:
//   - storage: Interface for storing and retrieving commit verifications
//   - sink: Interface for submitting aggregated reports
//   - config: Configuration containing committee and quorum settings
//
// Returns:
//   - *CommitReportAggregator: A new aggregator instance ready to process commit reports
//
// The returned aggregator must have StartBackground called to begin processing aggregation requests.
func NewCommitReportAggregator(storage common.CommitVerificationStore, sink common.Sink, quorum QuorumValidator, config *model.AggregatorConfig, logger logger.SugaredLogger, monitoring common.AggregatorMonitoring) *CommitReportAggregator {
	return &CommitReportAggregator{
		storage:               storage,
		sink:                  sink,
		messageIDChan:         make(chan aggregationRequest, config.Aggregation.ChannelBufferSize),
		backgroundWorkerCount: config.Aggregation.BackgroundWorkerCount,
		quorum:                quorum,
		monitoring:            monitoring,
		l:                     logger,
	}
}
