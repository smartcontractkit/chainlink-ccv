package model

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func getAllSignatureByAddress(report *CommitAggregatedReport) (map[string]protocol.Data, error) {
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
	return addressSignatures, nil
}

func findAllSignaturesValidInConfig(addressSignatures map[string]protocol.Data, config *QuorumConfig) []protocol.Data {
	signers := config.Signers

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
	return signatures
}

func MapAggregatedReportToVerifierResultProto(report *CommitAggregatedReport, c *Committee) (*pb.VerifierResult, error) {
	if len(report.Verifications) == 0 {
		return nil, fmt.Errorf("report does not contains verification")
	}

	addressSignatures, err := getAllSignatureByAddress(report)
	if err != nil {
		return nil, err
	}

	quorumConfig, ok := c.GetQuorumConfig(report.GetSourceChainSelector())
	if !ok {
		return nil, fmt.Errorf("quorum config not found for source selector: %d", report.GetSourceChainSelector())
	}

	destVerifierAddr := c.GetDestinationVerifierAddressBytes(report.GetDestinationSelector())
	if destVerifierAddr == nil {
		return nil, fmt.Errorf("destination verifier address not found for destination selector: %d", report.GetDestinationSelector())
	}

	signatures := findAllSignaturesValidInConfig(addressSignatures, quorumConfig)

	encodedSignatures, err := protocol.EncodeSignatures(signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signatures: %w", err)
	}

	// To create the full ccvData, prepend encodedSignatures with the version of the source verifier
	// The first verifierVersionLength bytes of the source verifier's return data constitute the version
	// Because we aggregate on the signed hash and this data is actually signed by verifiers it is safe to assume that all verifications have the same CCVVersion
	ccvVersion := report.GetVersion()
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
		ccvAddresses[i] = addr.Bytes()
	}

	return &pb.VerifierResult{
		Message:                report.GetProtoMessage(),
		MessageCcvAddresses:    ccvAddresses,
		MessageExecutorAddress: report.GetMessageExecutorAddress().Bytes(),
		CcvData:                ccvData,
		Metadata: &pb.VerifierResultMetadata{
			Timestamp:             report.WrittenAt.UnixMilli(),
			VerifierSourceAddress: quorumConfig.GetSourceVerifierAddressBytes(),
			VerifierDestAddress:   destVerifierAddr,
		},
	}, nil
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

	if proto.Message != nil {
		msg, err := ccvcommon.MapProtoMessageToProtocolMessage(proto.Message)
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
		ccvAddresses[i] = addr.Bytes()
	}

	proto := &pb.CommitteeVerifierNodeResult{
		CcvVersion:      record.CCVVersion,
		Signature:       record.Signature,
		CcvAddresses:    ccvAddresses,
		ExecutorAddress: record.MessageExecutorAddress.Bytes(),
	}

	if record.Message != nil {
		proto.Message = ccvcommon.MapProtocolMessageToProtoMessage(record.Message)
	}

	return proto
}
