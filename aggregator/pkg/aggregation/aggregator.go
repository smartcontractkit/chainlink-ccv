package aggregation

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/interfaces"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

type CommitReportAggregator struct {
	storage       interfaces.CommitVerificationStore
	sink          interfaces.Sink
	messageIdChan chan aggregationRequest
	config        model.AggregatorConfig
}

type aggregationRequest struct {
	CommitteeID string
	MessageID   model.MessageID
}

func (c *CommitReportAggregator) CheckAggregation(committee_id string, messageID model.MessageID) error {
	c.messageIdChan <- aggregationRequest{
		CommitteeID: committee_id,
		MessageID:   messageID,
	}
	return nil
}

func (c *CommitReportAggregator) checkAggregationAndSubmitComplete(committee_id string, messageID model.MessageID) (*model.CommitAggregatedReport, error) {
	verifications, err := c.storage.ListCommitVerificationByMessageID(context.Background(), committee_id, messageID)
	if err != nil {
		return nil, err
	}

	aggregatedReport := &model.CommitAggregatedReport{
		MessageID:     messageID,
		Verifications: verifications,
	}

	if ok, err := c.checkQuorum(aggregatedReport); err != nil {
		if err := c.sink.SubmitReport(aggregatedReport); err != nil {
			return nil, err
		}
	} else if !ok {
		return nil, nil
	}

	return nil, nil
}

func (c *CommitReportAggregator) checkQuorum(aggregatedReport *model.CommitAggregatedReport) (bool, error) {
	quorumConfig := c.config.Committees[aggregatedReport.CommitteeID].QuorumConfigs[aggregatedReport.GetDestinationSelector()]

	// Check if we have enough signatures to meet the quorum
	if len(aggregatedReport.Verifications) < int(len(quorumConfig.Signers))-int(quorumConfig.F) {
		return false, nil
	}

	return true, nil
}

func (c *CommitReportAggregator) StartBackground(ctx context.Context) {
	go func() {
		select {
		case request := <-c.messageIdChan:
			go c.checkAggregationAndSubmitComplete(request.CommitteeID, request.MessageID)
		case <-ctx.Done():
			return
		}
	}()
}

func NewCommitReportAggregator(storage interfaces.CommitVerificationStore, sink interfaces.Sink, config model.AggregatorConfig) *CommitReportAggregator {
	return &CommitReportAggregator{
		storage:       storage,
		sink:          sink,
		messageIdChan: make(chan aggregationRequest),
		config:        config,
	}
}
