// Package common provides shared interfaces
package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// Sink defines an interface for submitting aggregated commit reports.
type Sink interface {
	// SubmitAggregatedReport submits the aggregated commit report to the specified sink.
	// inserted is false (not an error) when a concurrent submission of the identical report won the race.
	SubmitAggregatedReport(ctx context.Context, report *model.CommitAggregatedReport) (inserted bool, err error)
}
