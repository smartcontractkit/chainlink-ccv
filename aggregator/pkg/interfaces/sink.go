package interfaces

import "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

type Sink interface {
	SubmitReport(report *model.CommitAggregatedReport) error
}
