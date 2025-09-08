// Package model defines the data structures and types used throughout the aggregator service.
package model

import "github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"

// CommitAggregatedReport represents a report of aggregated commit verifications.
type CommitAggregatedReport struct {
	MessageID     MessageID
	CommitteeID   string
	Verifications []*CommitVerificationRecord
	Timestamp     int64
}

// GetDestinationSelector retrieves the destination chain selector from the first verification record.
func (c *CommitAggregatedReport) GetDestinationSelector() uint64 {
	return c.GetMessage().DestChainSelector
}

func (c *CommitAggregatedReport) GetMessage() *aggregator.Message {
	return c.Verifications[0].Message
}
