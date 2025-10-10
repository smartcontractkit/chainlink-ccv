// Package model defines the data structures and types used throughout the aggregator service.
package model

import (
	"encoding/hex"
	"time"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// CommitAggregatedReport represents a report of aggregated commit verifications.
type CommitAggregatedReport struct {
	MessageID     MessageID
	CommitteeID   CommitteeID
	Verifications []*CommitVerificationRecord
	Timestamp     int64
}

type PaginatedAggregatedReports struct {
	Reports       []*CommitAggregatedReport
	NextPageToken *string
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

func (c *CommitAggregatedReport) GetMessage() *pb.Message {
	return c.Verifications[0].Message
}
