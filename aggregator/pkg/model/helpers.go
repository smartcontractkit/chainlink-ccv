package model

import (
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func MapProtoMessageToProtocolMessage(m *pb.Message) (*protocol.Message, error) {
	var ccvAndExecutorHash protocol.Bytes32
	if len(m.CcvAndExecutorHash) > 0 {
		copy(ccvAndExecutorHash[:], m.CcvAndExecutorHash)
	}

	msg := &protocol.Message{
		Version:              uint8(m.Version), //nolint:gosec // G115: Protocol-defined conversion
		SourceChainSelector:  protocol.ChainSelector(m.SourceChainSelector),
		DestChainSelector:    protocol.ChainSelector(m.DestChainSelector),
		SequenceNumber:       protocol.SequenceNumber(m.SequenceNumber),
		OnRampAddressLength:  uint8(m.OnRampAddressLength), //nolint:gosec // G115: Protocol-defined conversion
		OnRampAddress:        m.OnRampAddress,
		OffRampAddressLength: uint8(m.OffRampAddressLength), //nolint:gosec // G115: Protocol-defined conversion
		OffRampAddress:       m.OffRampAddress,
		Finality:             uint16(m.Finality), //nolint:gosec // G115: Protocol-defined conversion
		ExecutionGasLimit:    m.ExecutionGasLimit,
		CcipReceiveGasLimit:  m.CcipReceiveGasLimit,
		CcvAndExecutorHash:   ccvAndExecutorHash,
		SenderLength:         uint8(m.SenderLength), //nolint:gosec // G115: Protocol-defined conversion
		Sender:               m.Sender,
		ReceiverLength:       uint8(m.ReceiverLength), //nolint:gosec // G115: Protocol-defined conversion
		Receiver:             m.Receiver,
		DestBlobLength:       uint16(m.DestBlobLength), //nolint:gosec // G115: Protocol-defined conversion
		DestBlob:             m.DestBlob,
		TokenTransferLength:  uint16(m.TokenTransferLength),
		DataLength:           uint16(m.DataLength), //nolint:gosec // G115: Protocol-defined conversion
		Data:                 m.Data,
	}

	// Decode TokenTransfer if present
	if m.TokenTransferLength > 0 && len(m.TokenTransfer) > 0 {
		tt, err := protocol.DecodeTokenTransfer(m.TokenTransfer)
		if err != nil {
			return nil, fmt.Errorf("failed to decode token transfer: %w", err)
		}
		msg.TokenTransfer = tt
	} else {
		msg.TokenTransfer = nil
	}

	return msg, nil
}

func MapAggregatedReportToCCVDataProto(report *CommitAggregatedReport, c *Committee) (*pb.VerifierResult, error) {
	addressSignatures := make(map[string]protocol.Data)
	for _, verification := range report.Verifications {
		if verification.IdentifierSigner == nil {
			return nil, fmt.Errorf("missing IdentifierSigner in verification record")
		}

		addressKey := common.BytesToAddress(verification.IdentifierSigner.Address).Hex()
		addressSignatures[addressKey] = protocol.Data{
			R:      verification.IdentifierSigner.SignatureR,
			S:      verification.IdentifierSigner.SignatureS,
			Signer: common.Address(verification.IdentifierSigner.Address),
		}
	}

	quorumConfig, ok := c.GetQuorumConfig(report.GetDestinationSelector(), report.GetSourceChainSelector())
	if !ok {
		return nil, fmt.Errorf("quorum config not found for destination selector: %d, source selector: %d", report.GetDestinationSelector(), report.GetSourceChainSelector())
	}

	signers := quorumConfig.Signers

	signatures := make([]protocol.Data, 0)

	for _, signer := range signers {
		// Normalize address format to match the map key format (with 0x prefix)
		addr := signer.Address
		if !strings.HasPrefix(addr, "0x") {
			addr = "0x" + addr
		}

		// Find matching signature by comparing addresses case-insensitively
		var sig protocol.Data
		var found bool
		for key, s := range addressSignatures {
			if strings.EqualFold(key, addr) {
				sig = s
				found = true
				break
			}
		}

		if !found {
			continue
		}

		signatures = append(signatures, sig)
	}

	encodedSignatures, err := protocol.EncodeSignatures(signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signatures: %w", err)
	}

	// To create the full ccvData, prepend encodedSignatures with the version of the source verifier
	// The first verifierVersionLength bytes of the source verifier's return data constitute the version
	// Because we aggregate on the signed hash and this data is actually signed by verifiers it is safe to assume that all verifications have the same CCVVersion
	if len(report.Verifications) == 0 {
		return nil, fmt.Errorf("report does not contains verification")
	}

	ccvVersion := report.Verifications[0].CCVVersion
	if ccvVersion == nil {
		return nil, fmt.Errorf("ccv version is missing from verification")
	}
	ccvVersionLen := len(ccvVersion)
	if ccvVersionLen < committee.VerifierVersionLength {
		return nil, fmt.Errorf("ccv version is too short (expected at least %d bytes, got %d)", committee.VerifierVersionLength, ccvVersionLen)
	}
	ccvData := append(ccvVersion[:committee.VerifierVersionLength], encodedSignatures...)

	// Convert UnknownAddress types to [][]byte for protobuf
	ccvAddresses := make([][]byte, len(report.GetMessageCCVAddresses()))
	for i, addr := range report.GetMessageCCVAddresses() {
		ccvAddresses[i] = []byte(addr)
	}

	return &pb.VerifierResult{
		Message:                report.GetProtoMessage(),
		MessageCcvAddresses:    ccvAddresses,
		MessageExecutorAddress: []byte(report.GetMessageExecutorAddress()),
		CcvData:                ccvData,
		Metadata: &pb.VerifierResultMetadata{
			Timestamp:             timeToTimestampMillis(report.WrittenAt),
			VerifierSourceAddress: quorumConfig.GetSourceVerifierAddressBytes(),
			VerifierDestAddress:   quorumConfig.GetDestVerifierAddressBytes(),
		},
	}, nil
}

// timeToTimestampMillis converts time.Time to millisecond timestamp.
func timeToTimestampMillis(t time.Time) int64 {
	return t.UnixMilli()
}

// MapProtocolMessageToProtoMessage converts a protocol.Message to pb.Message.
func MapProtocolMessageToProtoMessage(m *protocol.Message) *pb.Message {
	var tokenTransferBytes []byte
	if m.TokenTransfer != nil {
		tokenTransferBytes = m.TokenTransfer.Encode()
	}

	return &pb.Message{
		Version:              uint32(m.Version),
		SourceChainSelector:  uint64(m.SourceChainSelector),
		DestChainSelector:    uint64(m.DestChainSelector),
		SequenceNumber:       uint64(m.SequenceNumber),
		OnRampAddressLength:  uint32(m.OnRampAddressLength),
		OnRampAddress:        m.OnRampAddress,
		OffRampAddressLength: uint32(m.OffRampAddressLength),
		OffRampAddress:       m.OffRampAddress,
		Finality:             uint32(m.Finality),
		ExecutionGasLimit:    m.ExecutionGasLimit,
		CcipReceiveGasLimit:  m.CcipReceiveGasLimit,
		CcvAndExecutorHash:   m.CcvAndExecutorHash[:],
		SenderLength:         uint32(m.SenderLength),
		Sender:               m.Sender,
		ReceiverLength:       uint32(m.ReceiverLength),
		Receiver:             m.Receiver,
		DestBlobLength:       uint32(m.DestBlobLength),
		DestBlob:             m.DestBlob,
		TokenTransferLength:  uint32(len(tokenTransferBytes)), //nolint:gosec // G115: Length bounded by TokenTransfer encoding
		TokenTransfer:        tokenTransferBytes,
		DataLength:           uint32(m.DataLength),
		Data:                 m.Data,
	}
}

// CommitVerificationRecordFromProto converts protobuf CommitteeVerifierNodeResult to domain model.
func CommitVerificationRecordFromProto(proto *pb.CommitteeVerifierNodeResult) (*CommitVerificationRecord, error) {
	// Convert [][]byte to []protocol.UnknownAddress
	ccvAddresses := make([]protocol.UnknownAddress, len(proto.CcvAddresses))
	for i, addr := range proto.CcvAddresses {
		ccvAddresses[i] = protocol.UnknownAddress(addr)
	}

	record := &CommitVerificationRecord{
		CCVVersion:             proto.CcvVersion,
		Signature:              proto.Signature,
		MessageCCVAddresses:    ccvAddresses,
		MessageExecutorAddress: protocol.UnknownAddress(proto.ExecutorAddress),
	}
	record.SetTimestampFromMillis(time.Now().UnixMilli())

	if proto.Message != nil {
		msg, err := MapProtoMessageToProtocolMessage(proto.Message)
		if err != nil {
			return nil, fmt.Errorf("failed to map proto message to protocol message: %w", err)
		}

		record.Message = msg

		messageID, err := record.Message.MessageID()
		if err != nil {
			return nil, fmt.Errorf("failed to compute message ID: %w", err)
		}
		record.MessageID = messageID[:]
	}

	return record, nil
}

// CommitVerificationRecordToProto converts domain model to protobuf CommitteeVerifierNodeResult.
func CommitVerificationRecordToProto(record *CommitVerificationRecord) *pb.CommitteeVerifierNodeResult {
	// Convert []protocol.UnknownAddress to [][]byte
	ccvAddresses := make([][]byte, len(record.MessageCCVAddresses))
	for i, addr := range record.MessageCCVAddresses {
		ccvAddresses[i] = []byte(addr)
	}

	proto := &pb.CommitteeVerifierNodeResult{
		CcvVersion:      record.CCVVersion,
		Signature:       record.Signature,
		CcvAddresses:    ccvAddresses,
		ExecutorAddress: []byte(record.MessageExecutorAddress),
	}

	if record.Message != nil {
		proto.Message = MapProtocolMessageToProtoMessage(record.Message)
	}

	return proto
}
