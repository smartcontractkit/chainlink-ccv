package model

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/common/pkg/signature"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

func MapProtoMessageToProtocolMessage(m *aggregator.Message) *types.Message {
	return &types.Message{
		Version:              uint8(m.Version), //nolint:gosec // G115: Protocol-defined conversion
		SourceChainSelector:  types.ChainSelector(m.SourceChainSelector),
		DestChainSelector:    types.ChainSelector(m.DestChainSelector),
		Nonce:                types.Nonce(m.Nonce),
		OnRampAddressLength:  uint8(m.OnRampAddressLength), //nolint:gosec // G115: Protocol-defined conversion
		OnRampAddress:        m.OnRampAddress,
		OffRampAddressLength: uint8(m.OffRampAddressLength), //nolint:gosec // G115: Protocol-defined conversion
		OffRampAddress:       m.OffRampAddress,
		Finality:             uint16(m.Finality),    //nolint:gosec // G115: Protocol-defined conversion
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

func MapAggregatedReportToCCVDataProto(report *CommitAggregatedReport, committees map[string]*Committee) (*aggregator.MessageWithCCVData, error) {
	participantSignatures := make(map[string]signature.Data)
	for _, verification := range report.Verifications {
		if verification.IdentifierSigner == nil {
			return nil, fmt.Errorf("missing IdentifierSigner in verification record")
		}

		participantSignatures[verification.IdentifierSigner.ParticipantID] = signature.Data{
			R:      verification.IdentifierSigner.SignatureR,
			S:      verification.IdentifierSigner.SignatureS,
			Signer: common.Address(verification.IdentifierSigner.Address),
		}
	}

	quorumConfig := FindQuorumConfigFromSelectorAndSourceVerifierAddress(committees, report.GetDestinationSelector(), report.GetSourceVerifierAddress())
	if quorumConfig == nil {
		return nil, fmt.Errorf("quorum config not found for chain selector: %d and address: %s", report.GetDestinationSelector(), common.BytesToAddress(report.GetSourceVerifierAddress()).Hex())
	}

	signers := quorumConfig.Signers

	signatures := make([]signature.Data, 0)
	// make sure all ccvData in reports are the same
	blobData := report.Verifications[0].BlobData
	for _, verification := range report.Verifications {
		if !bytes.Equal(blobData[:], verification.BlobData[:]) {
			return nil, fmt.Errorf("blobData are not the same between signers")
		}
	}

	for _, signer := range signers {
		sig, exists := participantSignatures[signer.ParticipantID]
		if !exists {
			// Skipping missing signatures (not all participants may have signed)
			continue
		}
		signatures = append(signatures, sig)
	}

	// Sort signatures by signer address for onchain compatibility
	sortedSignatures := make([]signature.Data, len(signatures))
	copy(sortedSignatures, signatures)
	signature.SortSignaturesBySigner(sortedSignatures)

	encodedSignatures, err := signature.EncodeSignaturesABI(blobData, sortedSignatures)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signatures: %w", err)
	}

	return &aggregator.MessageWithCCVData{
		Message:               report.GetMessage(),
		SourceVerifierAddress: report.GetSourceVerifierAddress(),
		DestVerifierAddress:   quorumConfig.GetOfframpAddressBytes(),
		CcvData:               encodedSignatures,
		Timestamp:             report.Timestamp,
	}, nil
}
