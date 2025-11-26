// Package model defines the data structures and types used throughout the aggregator service.
package model

import (
	"encoding/hex"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// CommitAggregatedReport represents a report of aggregated commit verifications.
type CommitAggregatedReport struct {
	MessageID     MessageID
	Verifications []*CommitVerificationRecord
	Sequence      int64
	// WrittenAt represents when the aggregated report was written to storage.
	// This field is used for ordering in the GetMessagesSince API to return reports
	// in the order they were finalized/stored, not the order of individual verifications.
	WrittenAt time.Time
}

type AggregatedReportBatch struct {
	Reports []*CommitAggregatedReport
	HasMore bool
}

func GetAggregatedReportID(messageID MessageID) string {
	return hex.EncodeToString(messageID)
}

func (c *CommitAggregatedReport) CalculateTimeToAggregation(aggregationTime time.Time) time.Duration {
	var minTime time.Time
	for v := range c.Verifications {
		if c.Verifications[v].GetTimestamp().Before(minTime) || minTime.IsZero() {
			minTime = c.Verifications[v].GetTimestamp()
		}
	}
	return aggregationTime.Sub(minTime)
}

func (c *CommitAggregatedReport) GetID() string {
	return GetAggregatedReportID(c.MessageID)
}

// GetDestinationSelector retrieves the destination chain selector from the first verification record.
func (c *CommitAggregatedReport) GetDestinationSelector() uint64 {
	return c.GetProtoMessage().DestChainSelector
}

func (c *CommitAggregatedReport) GetSourceChainSelector() uint64 {
	return c.GetProtoMessage().SourceChainSelector
}

func (c *CommitAggregatedReport) GetOffRampAddress() []byte {
	return c.GetProtoMessage().OffRampAddress
}

func (c *CommitAggregatedReport) GetMessageCCVAddresses() []protocol.UnknownAddress {
	return c.Verifications[0].MessageCCVAddresses
}

func (c *CommitAggregatedReport) GetMessageExecutorAddress() protocol.UnknownAddress {
	return c.Verifications[0].MessageExecutorAddress
}

// It is assumed that all verifications in the report have the same message since otherwise the message ID would not match.
func (c *CommitAggregatedReport) GetProtoMessage() *pb.Message {
	if len(c.Verifications) > 0 && c.Verifications[0].Message != nil {
		return MapProtocolMessageToProtoMessage(c.Verifications[0].Message)
	}
	return nil
}
