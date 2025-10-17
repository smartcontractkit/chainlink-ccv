// Package model defines the data structures and types used throughout the aggregator service.
package model

import (
	"encoding/hex"
	"math"
	"time"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// CommitAggregatedReport represents a report of aggregated commit verifications.
type CommitAggregatedReport struct {
	MessageID     MessageID
	CommitteeID   CommitteeID
	Verifications []*CommitVerificationRecord
	Sequence      int64
	// WrittenAt represents when the aggregated report was written to storage (in Unix seconds).
	// This field is used for ordering in the GetMessagesSince API to return reports
	// in the order they were finalized/stored, not the order of individual verifications.
	WrittenAt int64
}

type PaginatedAggregatedReports struct {
	Reports       []*CommitAggregatedReport
	NextPageToken *string
}

func normalizeTimestampToSeconds(timestamp int64) int64 {
	if timestamp <= 0 {
		return timestamp
	}
	digits := int(math.Log10(float64(timestamp))) + 1
	if digits > 10 {
		divisor := int64(math.Pow10(digits - 10))
		return timestamp / divisor
	}
	return timestamp
}

func (c *CommitAggregatedReport) GetMostRecentVerificationTimestamp() int64 {
	var mostRecent int64
	for _, v := range c.Verifications {
		vTimestampSeconds := normalizeTimestampToSeconds(v.GetTimestamp())
		if vTimestampSeconds > mostRecent {
			mostRecent = vTimestampSeconds
		}
	}
	return mostRecent
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
