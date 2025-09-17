package model

import (
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

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
	participantSignatures := make(map[string]struct {
		r [32]byte
		s [32]byte
	})
	for _, verification := range report.Verifications {
		if verification.IdentifierSigner == nil {
			return nil, fmt.Errorf("missing IdentifierSigner in verification record")
		}
		participantSignatures[verification.IdentifierSigner.ParticipantID] = struct {
			r [32]byte
			s [32]byte
		}{
			r: verification.IdentifierSigner.SignatureR,
			s: verification.IdentifierSigner.SignatureS,
		}
	}

	quorumConfig := FindQuorumConfigFromSelectorAndSourceVerifierAddress(committees, report.GetDestinationSelector(), report.GetSourceVerifierAddress())
	if quorumConfig == nil {
		return nil, fmt.Errorf("quorum config not found for chain selector: %d and address: %s", report.GetDestinationSelector(), common.BytesToAddress(report.GetSourceVerifierAddress()).Hex())
	}

	signers := quorumConfig.Signers

	// Create signature data - we need to recover signer addresses from the signatures
	// First, prepare the message hash and verifier blob for signature recovery
	message := report.GetMessage()
	protocolMessage := MapProtoMessageToProtocolMessage(message)
	messageHash, err := protocolMessage.MessageID()
	if err != nil {
		return nil, fmt.Errorf("failed to compute message ID: %w", err)
	}

	// Create ccvArgs from the verifier blob (nonce data)
	// For now, let's encode the nonce as ccvArgs (this should match what the verifier sends)
	nonce := message.GetNonce()
	ccvArgs := make([]byte, 8)
	binary.BigEndian.PutUint64(ccvArgs, uint64(nonce))

	// Calculate signature hash (same as verifier does)
	verifierBlobHash := signature.Keccak256(ccvArgs)
	var buf []byte
	buf = append(buf, messageHash[:]...)
	buf = append(buf, verifierBlobHash[:]...)
	signatureHash := signature.Keccak256(buf)

	var signatures []signature.SignatureData
	for _, signer := range signers {
		sig, exists := participantSignatures[signer.ParticipantID]
		if !exists {
			// Skipping missing signatures (not all participants may have signed)
			continue
		}

		// Recover signer address from signature
		sigBytes := make([]byte, 65)
		copy(sigBytes[0:32], sig.r[:])
		copy(sigBytes[32:64], sig.s[:])
		sigBytes[64] = 0 // Assume v=0 for now, might need to try both 0 and 1

		pubKey, err := crypto.SigToPub(signatureHash[:], sigBytes)
		if err != nil {
			// Try with v=1
			sigBytes[64] = 1
			pubKey, err = crypto.SigToPub(signatureHash[:], sigBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to recover signer address for participant %s: %w", signer.ParticipantID, err)
			}
		}

		signerAddr := crypto.PubkeyToAddress(*pubKey)

		signatures = append(signatures, signature.SignatureData{
			R:      sig.r,
			S:      sig.s,
			Signer: signerAddr,
		})
	}

	encodedSignatures, err := signature.EncodeSignaturesABI(ccvArgs, signatures)
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
