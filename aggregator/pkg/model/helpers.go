package model

import (
	"bytes"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/protocol"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

const (
	// The number of bytes used to represent the verifier version.
	verifierVersionLength = 4
)

func MapProtoMessageToProtocolMessage(m *pb.Message) *protocol.Message {
	return &protocol.Message{
		Version:              uint8(m.Version), //nolint:gosec // G115: Protocol-defined conversion
		SourceChainSelector:  protocol.ChainSelector(m.SourceChainSelector),
		DestChainSelector:    protocol.ChainSelector(m.DestChainSelector),
		Nonce:                protocol.Nonce(m.Nonce),
		OnRampAddressLength:  uint8(m.OnRampAddressLength), //nolint:gosec // G115: Protocol-defined conversion
		OnRampAddress:        m.OnRampAddress,
		OffRampAddressLength: uint8(m.OffRampAddressLength), //nolint:gosec // G115: Protocol-defined conversion
		OffRampAddress:       m.OffRampAddress,
		Finality:             uint16(m.Finality), //nolint:gosec // G115: Protocol-defined conversion
		GasLimit:             m.GasLimit,
		SenderLength:         uint8(m.SenderLength), //nolint:gosec // G115: Protocol-defined conversion
		Sender:               m.Sender,
		ReceiverLength:       uint8(m.ReceiverLength), //nolint:gosec // G115: Protocol-defined conversion
		Receiver:             m.Receiver,
		DestBlobLength:       uint16(m.DestBlobLength), //nolint:gosec // G115: Protocol-defined conversion
		DestBlob:             m.DestBlob,
		TokenTransferLength:  uint16(m.TokenTransferLength), //nolint:gosec // G115: Protocol-defined conversion
		TokenTransfer:        m.TokenTransfer,
		DataLength:           uint16(m.DataLength), //nolint:gosec // G115: Protocol-defined conversion
		Data:                 m.Data,
	}
}

func compareStringCaseInsensitive(a, b string) bool {
	return bytes.EqualFold([]byte(a), []byte(b))
}

func MapAggregatedReportToCCVDataProto(report *CommitAggregatedReport, committees map[string]*Committee) (*pb.VerifierResult, error) {
	participantSignatures := make(map[string]protocol.Data)
	for _, verification := range report.Verifications {
		if verification.IdentifierSigner == nil {
			return nil, fmt.Errorf("missing IdentifierSigner in verification record")
		}

		participantSignatures[verification.IdentifierSigner.ParticipantID] = protocol.Data{
			R:      verification.IdentifierSigner.SignatureR,
			S:      verification.IdentifierSigner.SignatureS,
			Signer: common.Address(verification.IdentifierSigner.Address),
		}
	}

	quorumConfig := FindQuorumConfigFromSelectorAndSourceVerifierAddress(committees, report.GetSourceChainSelector(), report.GetDestinationSelector(), report.GetSourceVerifierAddress())
	if quorumConfig == nil {
		return nil, fmt.Errorf("quorum config not found for chain selector: %d and address: %s", report.GetDestinationSelector(), common.BytesToAddress(report.GetSourceVerifierAddress()).Hex())
	}

	signers := quorumConfig.Signers

	signatures := make([]protocol.Data, 0)

	for _, signer := range signers {
		sig, exists := participantSignatures[signer.ParticipantID]
		if !exists {
			// Skipping missing signatures (not all participants may have signed)
			continue
		}

		recoveredAddress := sig.Signer
		validAddresses := signer.Addresses
		addressValid := false
		for _, addr := range validAddresses {
			if compareStringCaseInsensitive(addr, recoveredAddress.Hex()) {
				addressValid = true
				break
			}
		}

		if addressValid {
			signatures = append(signatures, sig)
		}
	}

	// Encode signatures using simple format (sorting is handled internally)
	encodedSignatures, err := protocol.EncodeSignatures(signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signatures: %w", err)
	}

	// To create the full ccvData, prepend encodedSignatures with the version of the source verifier
	// The first verifierVersionLength bytes of the source verifier's return data constitute the version
	var ccvData []byte
	for _, receipt := range report.WinningReceiptBlobs {
		if bytes.Equal(receipt.Issuer, report.GetSourceVerifierAddress()) {
			if receipt.Blob == nil {
				return nil, fmt.Errorf("source verifier return blob is missing from receipt")
			}
			blobLen := len(receipt.Blob)
			if blobLen < verifierVersionLength {
				return nil, fmt.Errorf("source verifier return blob is too short (expected at least %d bytes, got %d)", verifierVersionLength, blobLen)
			}
			ccvData = append(receipt.Blob[:verifierVersionLength], encodedSignatures...)
			break
		}
	}
	if len(ccvData) == 0 {
		return nil, fmt.Errorf("source verifier receipt not found in winning receipts, unable to create CCV data")
	}

	return &pb.VerifierResult{
		Message:               report.GetProtoMessage(),
		SourceVerifierAddress: report.GetSourceVerifierAddress(),
		DestVerifierAddress:   quorumConfig.GetDestVerifierAddressBytes(),
		CcvData:               ccvData,
		Timestamp:             timeToTimestampMillis(report.WrittenAt),
		Sequence:              report.Sequence,
	}, nil
}

// timestampMillisToTime converts millisecond timestamp to time.Time in UTC.
func timestampMillisToTime(timestampMillis int64) time.Time {
	return time.UnixMilli(timestampMillis).UTC()
}

// timeToTimestampMillis converts time.Time to millisecond timestamp.
func timeToTimestampMillis(t time.Time) int64 {
	return t.UnixMilli()
}

// MapProtocolMessageToProtoMessage converts a protocol.Message to pb.Message.
func MapProtocolMessageToProtoMessage(m *protocol.Message) *pb.Message {
	return &pb.Message{
		Version:              uint32(m.Version),
		SourceChainSelector:  uint64(m.SourceChainSelector),
		DestChainSelector:    uint64(m.DestChainSelector),
		Nonce:                uint64(m.Nonce),
		OnRampAddressLength:  uint32(m.OnRampAddressLength),
		OnRampAddress:        m.OnRampAddress,
		OffRampAddressLength: uint32(m.OffRampAddressLength),
		OffRampAddress:       m.OffRampAddress,
		Finality:             uint32(m.Finality),
		GasLimit:             m.GasLimit,
		SenderLength:         uint32(m.SenderLength),
		Sender:               m.Sender,
		ReceiverLength:       uint32(m.ReceiverLength),
		Receiver:             m.Receiver,
		DestBlobLength:       uint32(m.DestBlobLength),
		DestBlob:             m.DestBlob,
		TokenTransferLength:  uint32(m.TokenTransferLength),
		TokenTransfer:        m.TokenTransfer,
		DataLength:           uint32(m.DataLength),
		Data:                 m.Data,
	}
}

// CommitVerificationRecordFromProto converts protobuf MessageWithCCVNodeData to domain model.
func CommitVerificationRecordFromProto(proto *pb.MessageWithCCVNodeData) *CommitVerificationRecord {
	record := &CommitVerificationRecord{
		MessageID:             proto.MessageId,
		SourceVerifierAddress: proto.SourceVerifierAddress,
		BlobData:              proto.BlobData,
		CcvData:               proto.CcvData,
		Timestamp:             timestampMillisToTime(proto.Timestamp),
		ReceiptBlobs:          ReceiptBlobsFromProto(proto.ReceiptBlobs),
	}

	if proto.Message != nil {
		record.Message = MapProtoMessageToProtocolMessage(proto.Message)
	}

	return record
}

// CommitVerificationRecordToProto converts domain model to protobuf MessageWithCCVNodeData.
func CommitVerificationRecordToProto(record *CommitVerificationRecord) *pb.MessageWithCCVNodeData {
	proto := &pb.MessageWithCCVNodeData{
		MessageId:             record.MessageID,
		SourceVerifierAddress: record.SourceVerifierAddress,
		BlobData:              record.BlobData,
		CcvData:               record.CcvData,
		Timestamp:             timeToTimestampMillis(record.Timestamp),
		ReceiptBlobs:          ReceiptBlobsToProto(record.ReceiptBlobs),
	}

	if record.Message != nil {
		proto.Message = MapProtocolMessageToProtoMessage(record.Message)
	}

	return proto
}
