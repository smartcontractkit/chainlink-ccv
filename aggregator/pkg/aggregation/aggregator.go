// Package aggregation provides commit report aggregation functionality for the aggregator service.
package aggregation

import (
	"context"
	"time"

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
	storage       common.CommitVerificationStore
	sink          common.Sink
	messageIDChan chan aggregationRequest
	quorum        QuorumValidator
	l             logger.SugaredLogger
}

type aggregationRequest struct {
	// CommitteeID is the ID of the committee for the aggregation request.
	CommitteeID string
	MessageID   model.MessageID
}

// CheckAggregation enqueues a new aggregation request for the specified message ID.
func (c *CommitReportAggregator) CheckAggregation(messageID model.MessageID, committeeID string) error {
	go func() {
		c.messageIDChan <- aggregationRequest{
			MessageID:   messageID,
			CommitteeID: committeeID,
		}
	}()
	return nil
}

func (c *CommitReportAggregator) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, c.l)
}

func (c *CommitReportAggregator) checkAggregationAndSubmitComplete(ctx context.Context, messageID model.MessageID, committee string) (*model.CommitAggregatedReport, error) {
	lggr := c.logger(ctx)
	lggr.Debugw("Starting aggregation check")
	lggr = lggr.With("messageID", messageID, "committee", committee)
	lggr.Infof("Checking aggregation for message ID: %s, committee: %s", messageID, committee)
	verifications, err := c.storage.ListCommitVerificationByMessageID(ctx, messageID, committee)
	if err != nil {
		lggr.Errorw("Failed to list verifications", "error", err)
		return nil, err
	}

	lggr.Debugw("Verifications retrieved", "count", len(verifications))

	aggregatedReport := &model.CommitAggregatedReport{
		MessageID:     messageID,
		CommitteeID:   committee,
		Verifications: verifications,
		Timestamp:     time.Now().Unix(),
	}

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
		lggr.Infow("Report submitted successfully", "verifications", len(verifications))
	} else {
		lggr.Infow("Quorum not met, not submitting report", "verifications", len(verifications))
	}

	return nil, nil
}

// StartBackground begins processing aggregation requests in the background.
func (c *CommitReportAggregator) StartBackground(ctx context.Context) {
	go func() {
		for {
			select {
			case request := <-c.messageIDChan:
				go func() {
					ctx := scope.WithMessageID(context.Background(), request.MessageID)
					ctx = scope.WithCommitteeID(ctx, request.CommitteeID)
					_, err := c.checkAggregationAndSubmitComplete(ctx, request.MessageID, request.CommitteeID)
					if err != nil {
						c.logger(ctx).Errorw("Failed to process aggregation request", "error", err)
					}
				}()
			case <-ctx.Done():
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
func NewCommitReportAggregator(storage common.CommitVerificationStore, sink common.Sink, quorum QuorumValidator, logger logger.SugaredLogger) *CommitReportAggregator {
	return &CommitReportAggregator{
		storage:       storage,
		sink:          sink,
		messageIDChan: make(chan aggregationRequest, 1000),
		quorum:        quorum,
		l:             logger,
	}
}
