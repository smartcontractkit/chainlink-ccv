package model

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

func IsSourceVerifierInCCVAddresses(sourceVerifierAddr protocol.UnknownAddress, ccvAddresses []protocol.UnknownAddress) bool {
	for _, addr := range ccvAddresses {
		if sourceVerifierAddr.Equal(addr) {
			return true
		}
	}
	return false
}

func getAllSignatureByAddress(report *CommitAggregatedReport) (map[string]protocol.Data, error) {
	addressSignatures := make(map[string]protocol.Data)
	for _, verification := range report.Verifications {
		if verification.SignerIdentifier == nil {
			return nil, fmt.Errorf("missing SignerIdentifier in verification record")
		}

		r, s, _, err := protocol.DecodeSingleECDSASignature(verification.Signature)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signature: %w", err)
		}

		addressKey := common.BytesToAddress(verification.SignerIdentifier.Identifier).Hex()
		addressSignatures[addressKey] = protocol.Data{
			R:      r,
			S:      s,
			Signer: common.BytesToAddress(verification.SignerIdentifier.Identifier),
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

func MapAggregatedReportToVerifierResultProto(report *CommitAggregatedReport, c *Committee) (*verifierpb.VerifierResult, error) {
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

	destVerifierAddr, ok := c.GetDestinationVerifierAddress(report.GetDestinationSelector())
	if !ok {
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

	protoMsg := report.GetProtoMessage()
	if protoMsg == nil {
		return nil, fmt.Errorf("failed to convert message to proto format")
	}

	return &verifierpb.VerifierResult{
		Message:                protoMsg,
		MessageCcvAddresses:    ccvAddresses,
		MessageExecutorAddress: report.GetMessageExecutorAddress().Bytes(),
		CcvData:                ccvData,
		Metadata: &verifierpb.VerifierResultMetadata{
			Timestamp:             report.WrittenAt.UnixMilli(),
			VerifierSourceAddress: quorumConfig.GetSourceVerifierAddress().Bytes(),
			VerifierDestAddress:   destVerifierAddr.Bytes(),
		},
	}, nil
}

// CommitVerificationRecordFromProto converts protobuf CommitteeVerifierNodeResult to domain model.
func CommitVerificationRecordFromProto(proto *committeepb.CommitteeVerifierNodeResult) (*CommitVerificationRecord, error) {
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
func CommitVerificationRecordToProto(record *CommitVerificationRecord) (*committeepb.CommitteeVerifierNodeResult, error) {
	// Convert []protocol.UnknownAddress to [][]byte
	ccvAddresses := make([][]byte, len(record.MessageCCVAddresses))
	for i, addr := range record.MessageCCVAddresses {
		ccvAddresses[i] = addr.Bytes()
	}

	proto := &committeepb.CommitteeVerifierNodeResult{
		CcvVersion:      record.CCVVersion,
		Signature:       record.Signature,
		CcvAddresses:    ccvAddresses,
		ExecutorAddress: record.MessageExecutorAddress.Bytes(),
	}

	if record.Message != nil {
		msg, err := ccvcommon.MapProtocolMessageToProtoMessage(record.Message)
		if err != nil {
			return nil, fmt.Errorf("failed to map protocol message to proto: %w", err)
		}
		proto.Message = msg
	}

	return proto, nil
}
