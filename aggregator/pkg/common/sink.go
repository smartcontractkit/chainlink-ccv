// Package common provides shared interfaces
package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// Sink defines an interface for submitting aggregated commit reports.
type Sink interface {
	SubmitReport(ctx context.Context, report *model.CommitAggregatedReport) error
}
