// Package model defines the data structures and types used throughout the aggregator service.
package model

import "fmt"

// CommitAggregatedReport represents a report of aggregated commit verifications.
type CommitAggregatedReport struct {
	MessageID     MessageID
	CommitteeID   string
	Verifications []*CommitVerificationRecord
	Timestamp     int64
}

func (c *CommitAggregatedReport) GetID() *CommitVerificationAggregatedReportIdentifier {
	return &CommitVerificationAggregatedReportIdentifier{
		MessageID:   c.MessageID,
		CommitteeID: c.CommitteeID,
	}
}

// GetDestinationSelector retrieves the destination chain selector from the first verification record.
func (c *CommitAggregatedReport) GetDestinationSelector() uint64 {
	return c.Verifications[0].DestChainSelector
}

// CommitVerificationAggregatedReportIdentifier uniquely identifies a commit verification aggregated report.
type CommitVerificationAggregatedReportIdentifier struct {
	MessageID   MessageID
	CommitteeID string
}

// ToIdentifier converts the CommitVerificationAggregatedReportIdentifier to a string identifier.
func (c CommitVerificationAggregatedReportIdentifier) ToIdentifier() string {
	return fmt.Sprintf("%x:%s", c.MessageID, c.CommitteeID)
}
