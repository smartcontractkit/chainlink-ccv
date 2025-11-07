// Package model defines the data structures and types used throughout the aggregator service.
package model

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"time"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// ReceiptBlob represents a receipt blob in the domain model.
type ReceiptBlob struct {
	// Issuer is the address of the verifier that issued this receipt blob
	Issuer []byte
	// DestGasLimit is the gas limit for the destination chain
	DestGasLimit uint64
	// DestBytesOverhead is the bytes overhead for the destination chain
	DestBytesOverhead uint32
	// Blob is the actual receipt blob data
	Blob []byte
	// ExtraArgs contains additional arguments for the receipt blob
	ExtraArgs []byte
}

// ToProto converts the domain model ReceiptBlob to a protobuf ReceiptBlob.
func (r *ReceiptBlob) ToProto() *pb.ReceiptBlob {
	if r == nil {
		return nil
	}
	return &pb.ReceiptBlob{
		Issuer:            r.Issuer,
		DestGasLimit:      r.DestGasLimit,
		DestBytesOverhead: r.DestBytesOverhead,
		Blob:              r.Blob,
		ExtraArgs:         r.ExtraArgs,
	}
}

// ReceiptBlobFromProto converts a protobuf ReceiptBlob to the domain model.
func ReceiptBlobFromProto(pb *pb.ReceiptBlob) *ReceiptBlob {
	if pb == nil {
		return nil
	}
	return &ReceiptBlob{
		Issuer:            pb.Issuer,
		DestGasLimit:      pb.DestGasLimit,
		DestBytesOverhead: pb.DestBytesOverhead,
		Blob:              pb.Blob,
		ExtraArgs:         pb.ExtraArgs,
	}
}

// ReceiptBlobsToProto converts a slice of domain model ReceiptBlobs to protobuf ReceiptBlobs.
func ReceiptBlobsToProto(blobs []*ReceiptBlob) []*pb.ReceiptBlob {
	if blobs == nil {
		return nil
	}
	result := make([]*pb.ReceiptBlob, len(blobs))
	for i, blob := range blobs {
		result[i] = blob.ToProto()
	}
	return result
}

// ReceiptBlobsFromProto converts a slice of protobuf ReceiptBlobs to domain model ReceiptBlobs.
func ReceiptBlobsFromProto(pbs []*pb.ReceiptBlob) []*ReceiptBlob {
	if pbs == nil {
		return nil
	}
	result := make([]*ReceiptBlob, len(pbs))
	for i, pb := range pbs {
		result[i] = ReceiptBlobFromProto(pb)
	}
	return result
}

// Less implements a deterministic comparison for ReceiptBlob instances.
// It compares by Issuer, then DestGasLimit, then DestBytesOverhead, then Blob, then ExtraArgs.
func (r *ReceiptBlob) Less(other *ReceiptBlob) bool {
	if r == nil || other == nil {
		return r == nil && other != nil
	}

	// Compare by Issuer (byte slice)
	if cmp := bytes.Compare(r.Issuer, other.Issuer); cmp != 0 {
		return cmp < 0
	}

	// Compare by DestGasLimit
	if r.DestGasLimit != other.DestGasLimit {
		return r.DestGasLimit < other.DestGasLimit
	}

	// Compare by DestBytesOverhead
	if r.DestBytesOverhead != other.DestBytesOverhead {
		return r.DestBytesOverhead < other.DestBytesOverhead
	}

	// Compare by Blob (byte slice)
	if cmp := bytes.Compare(r.Blob, other.Blob); cmp != 0 {
		return cmp < 0
	}

	// Compare by ExtraArgs (byte slice)
	return bytes.Compare(r.ExtraArgs, other.ExtraArgs) < 0
}

// receiptBlobJSON is a helper struct for JSON serialization with hex-encoded byte fields.
type receiptBlobJSON struct {
	Issuer            string `json:"issuer"`
	DestGasLimit      uint64 `json:"dest_gas_limit"`
	DestBytesOverhead uint32 `json:"dest_bytes_overhead"`
	Blob              string `json:"blob"`
	ExtraArgs         string `json:"extra_args"`
}

// MarshalJSON implements json.Marshaler for ReceiptBlob.
func (r *ReceiptBlob) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}

	helper := receiptBlobJSON{
		Issuer:            hex.EncodeToString(r.Issuer),
		DestGasLimit:      r.DestGasLimit,
		DestBytesOverhead: r.DestBytesOverhead,
		Blob:              hex.EncodeToString(r.Blob),
		ExtraArgs:         hex.EncodeToString(r.ExtraArgs),
	}

	return json.Marshal(helper)
}

// UnmarshalJSON implements json.Unmarshaler for ReceiptBlob.
func (r *ReceiptBlob) UnmarshalJSON(data []byte) error {
	var helper receiptBlobJSON
	if err := json.Unmarshal(data, &helper); err != nil {
		return err
	}

	var err error
	r.Issuer, err = hex.DecodeString(helper.Issuer)
	if err != nil {
		return err
	}

	r.DestGasLimit = helper.DestGasLimit
	r.DestBytesOverhead = helper.DestBytesOverhead

	r.Blob, err = hex.DecodeString(helper.Blob)
	if err != nil {
		return err
	}

	r.ExtraArgs, err = hex.DecodeString(helper.ExtraArgs)
	if err != nil {
		return err
	}

	return nil
}

// SerializeReceiptBlobsJSON serializes a slice of ReceiptBlob to JSON bytes.
func SerializeReceiptBlobsJSON(blobs []*ReceiptBlob) ([]byte, error) {
	if blobs == nil {
		return nil, nil
	}
	return json.Marshal(blobs)
}

// DeserializeReceiptBlobsJSON deserializes JSON bytes to a slice of ReceiptBlob.
func DeserializeReceiptBlobsJSON(data []byte) ([]*ReceiptBlob, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var blobs []*ReceiptBlob
	if err := json.Unmarshal(data, &blobs); err != nil {
		return nil, err
	}

	return blobs, nil
}

// CommitAggregatedReport represents a report of aggregated commit verifications.
type CommitAggregatedReport struct {
	MessageID     MessageID
	CommitteeID   CommitteeID
	Verifications []*CommitVerificationRecord
	Sequence      int64
	// WrittenAt represents when the aggregated report was written to storage.
	// This field is used for ordering in the GetMessagesSince API to return reports
	// in the order they were finalized/stored, not the order of individual verifications.
	WrittenAt time.Time
	// WinningReceiptBlobs contains the receipt blob set that achieved consensus during aggregation.
	// This is computed once during aggregation and stored with the aggregated report.
	WinningReceiptBlobs []*ReceiptBlob
}

type PaginatedAggregatedReports struct {
	Reports       []*CommitAggregatedReport
	NextPageToken *string
}

func (c *CommitAggregatedReport) GetMostRecentVerificationTimestamp() time.Time {
	var mostRecent time.Time
	for _, v := range c.Verifications {
		vTimestamp := v.GetTimestamp()
		if vTimestamp.After(mostRecent) {
			mostRecent = vTimestamp
		}
	}
	return mostRecent
}

func GetAggregatedReportID(messageID MessageID, committeeID CommitteeID) string {
	return hex.EncodeToString(messageID) + ":" + committeeID
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
	return GetAggregatedReportID(c.MessageID, c.CommitteeID)
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

func (c *CommitAggregatedReport) GetSourceVerifierAddress() []byte {
	return c.Verifications[0].SourceVerifierAddress
}

// It is assumed that all verifications in the report have the same message since otherwise the message ID would not match.
func (c *CommitAggregatedReport) GetProtoMessage() *pb.Message {
	if len(c.Verifications) > 0 && c.Verifications[0].Message != nil {
		return MapProtocolMessageToProtoMessage(c.Verifications[0].Message)
	}
	return nil
}
