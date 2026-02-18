package model

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

func IsSourceVerifierInCCVAddresses(sourceVerifierAddr protocol.UnknownAddress, ccvAddresses []protocol.UnknownAddress) bool {
	return slices.ContainsFunc(ccvAddresses, sourceVerifierAddr.Equal)
}

func normalizeHexAddress(addr string) string {
	if !strings.HasPrefix(addr, "0x") {
		addr = "0x" + addr
	}
	return strings.ToLower(addr)
}

func signaturesByAddress(report *CommitAggregatedReport) (map[string]protocol.Data, error) {
	sigs := make(map[string]protocol.Data, len(report.Verifications))
	for _, verification := range report.Verifications {
		if verification.SignerIdentifier == nil {
			return nil, fmt.Errorf("missing SignerIdentifier in verification record")
		}

		r, s, _, err := protocol.DecodeSingleECDSASignature(verification.Signature)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signature: %w", err)
		}

		addr := common.BytesToAddress(verification.SignerIdentifier.Identifier)
		key := normalizeHexAddress(addr.Hex())
		sigs[key] = protocol.Data{
			R:      r,
			S:      s,
			Signer: addr,
		}
	}
	return sigs, nil
}

func filterSignaturesByQuorum(sigs map[string]protocol.Data, config *QuorumConfig) ([]protocol.Data, error) {
	if config == nil {
		return nil, fmt.Errorf("quorum config is nil")
	}
	seen := make(map[string]struct{}, len(config.Signers))
	signatures := make([]protocol.Data, 0, len(config.Signers))
	for _, signer := range config.Signers {
		key := normalizeHexAddress(signer.Address)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if sig, ok := sigs[key]; ok {
			signatures = append(signatures, sig)
		}
	}
	if len(signatures) < int(config.Threshold) {
		return nil, fmt.Errorf("valid signatures (%d) below quorum threshold (%d)", len(signatures), config.Threshold)
	}
	return signatures, nil
}

func encodeQuorumSignatures(report *CommitAggregatedReport, quorumConfig *QuorumConfig) ([]byte, error) {
	sigs, err := signaturesByAddress(report)
	if err != nil {
		return nil, err
	}

	quorumSignatures, err := filterSignaturesByQuorum(sigs, quorumConfig)
	if err != nil {
		return nil, err
	}

	encoded, err := protocol.EncodeSignatures(quorumSignatures)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signatures: %w", err)
	}
	return encoded, nil
}

func MapAggregatedReportToVerifierResultProto(report *CommitAggregatedReport, c *Committee) (*verifierpb.VerifierResult, error) {
	if len(report.Verifications) == 0 {
		return nil, fmt.Errorf("report does not contain any verifications")
	}

	quorumConfig, ok := c.GetQuorumConfig(report.GetSourceChainSelector())
	if !ok {
		return nil, fmt.Errorf("quorum config not found for source selector: %d", report.GetSourceChainSelector())
	}

	destVerifierAddr, ok := c.GetDestinationVerifierAddress(report.GetDestinationSelector())
	if !ok {
		return nil, fmt.Errorf("destination verifier address not found for destination selector: %d", report.GetDestinationSelector())
	}

	encodedSignatures, err := encodeQuorumSignatures(report, quorumConfig)
	if err != nil {
		return nil, fmt.Errorf("encoding quorum signatures: %w", err)
	}

	ccvVersion := report.GetVersion()
	if ccvVersion == nil {
		return nil, fmt.Errorf("ccv version is missing from verification")
	}
	if len(ccvVersion) < committee.VerifierVersionLength {
		return nil, fmt.Errorf("ccv version is too short (expected at least %d bytes, got %d)", committee.VerifierVersionLength, len(ccvVersion))
	}
	ccvData := append(ccvVersion[:committee.VerifierVersionLength], encodedSignatures...)

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
