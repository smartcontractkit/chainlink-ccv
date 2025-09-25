// Package model defines the data structures and types used throughout the aggregator service.
package model

import (
	"encoding/hex"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

// CommitAggregatedReport represents a report of aggregated commit verifications.
type CommitAggregatedReport struct {
	MessageID     MessageID
	CommitteeID   CommitteeID
	Verifications []*CommitVerificationRecord
	Timestamp     int64
}

func GetAggregatedReportID(messageID MessageID, committeeID CommitteeID) string {
	return hex.EncodeToString(messageID) + ":" + committeeID
}

func (c *CommitAggregatedReport) CalculateTimeToAggregation(aggregationTime time.Time) time.Duration {
	var minTime int64
	for v := range c.Verifications {
		if c.Verifications[v].GetTimestamp() < minTime || minTime == 0 {
			minTime = c.Verifications[v].GetTimestamp()
		}
	}
	return aggregationTime.Sub(time.UnixMicro(minTime))
}

func (c *CommitAggregatedReport) GetID() string {
	return GetAggregatedReportID(c.MessageID, c.CommitteeID)
}

// GetDestinationSelector retrieves the destination chain selector from the first verification record.
func (c *CommitAggregatedReport) GetDestinationSelector() uint64 {
	return c.GetMessage().DestChainSelector
}

func (c *CommitAggregatedReport) GetSourceChainSelector() uint64 {
	return c.GetMessage().SourceChainSelector
}

func (c *CommitAggregatedReport) GetOffRampAddress() []byte {
	return c.GetMessage().OffRampAddress
}

func (c *CommitAggregatedReport) GetSourceVerifierAddress() []byte {
	return c.Verifications[0].SourceVerifierAddress
}

func (c *CommitAggregatedReport) GetMessage() *aggregator.Message {
	return c.Verifications[0].Message
}

// MessageCommitteePair represents a unique combination of messageID and committeeID
// found in verification records, used for orphan detection.
type MessageCommitteePair struct {
	MessageID   MessageID
	CommitteeID CommitteeID
}
