// Package common provides shared interfaces
package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// Sink defines an interface for submitting aggregated commit reports.
type Sink interface {
	// SubmitAggregatedReport submits the aggregated commit report to the specified sink
	SubmitAggregatedReport(ctx context.Context, report *model.CommitAggregatedReport) error
}
