package aggregation

import "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

type AggregatorSinkStub struct {
}

func (s *AggregatorSinkStub) SubmitReport(report *model.CommitAggregatedReport) error {
	return nil
}
