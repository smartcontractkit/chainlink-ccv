package aggregation

import "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

// AggregatorSinkStub is a stub implementation of the Sink interface for testing purposes.
type AggregatorSinkStub struct {
}

// SubmitReport is a stub implementation of the SubmitReport method for testing purposes.
func (s *AggregatorSinkStub) SubmitReport(report *model.CommitAggregatedReport) error {
	return nil
}
