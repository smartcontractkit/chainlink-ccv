package model

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

func MapProtoMessageToProtocolMessage(m *aggregator.Message) *types.Message {
	return &types.Message{
		Version:              uint8(m.Version), //nolint:gosec // G115: Protocol-defined conversion
		SourceChainSelector:  types.ChainSelector(m.SourceChainSelector),
		DestChainSelector:    types.ChainSelector(m.DestChainSelector),
		SequenceNumber:       types.SeqNum(m.SequenceNumber),
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

	signers := FindSignersFromSelectorAndOfframp(committees, report.GetDestinationSelector(), report.GetMessage().OffRampAddress)

	rs := make([][32]byte, 0, len(signers))
	ss := make([][32]byte, 0, len(signers))
	for _, signer := range signers {
		sig, exists := participantSignatures[signer.ParticipantID]
		if !exists {
			// Skipping missing signatures (not all participants may have signed)
			continue
		}
		rs = append(rs, sig.r)
		ss = append(ss, sig.s)
	}

	encodedSignatures, err := EncodeSignatures(rs, ss)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signatures: %w", err)
	}

	return &aggregator.MessageWithCCVData{
		Message:               report.GetMessage(),
		SourceVerifierAddress: report.GetMessage().OnRampAddress,
		DestVerifierAddress:   report.GetMessage().OffRampAddress,
		CcvData:               encodedSignatures,
		Timestamp:             report.Timestamp,
	}, nil
}

func EncodeSignatures(rs, ss [][32]byte) ([]byte, error) {
	if len(rs) != len(ss) {
		return nil, fmt.Errorf("rs and ss arrays must have the same length")
	}

	var buf bytes.Buffer

	// Encode array length as uint16 (big-endian)
	arrayLen := uint16(len(rs)) //nolint:gosec // G115: Protocol-defined conversion
	if err := binary.Write(&buf, binary.BigEndian, arrayLen); err != nil {
		return nil, err
	}

	// Encode rs array
	for _, r := range rs {
		buf.Write(r[:])
	}

	// Encode ss array
	for _, s := range ss {
		buf.Write(s[:])
	}

	return buf.Bytes(), nil
}

func DecodeSignatures(data []byte) (rs, ss [][32]byte, err error) {
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("data too short to contain length")
	}

	// Read array length
	arrayLen := binary.BigEndian.Uint16(data[:2])
	expectedLen := 2 + int(arrayLen)*32*2
	if len(data) != expectedLen {
		return nil, nil, fmt.Errorf("invalid data length: expected %d, got %d", expectedLen, len(data))
	}

	rs = make([][32]byte, arrayLen)
	ss = make([][32]byte, arrayLen)

	// Offsets
	offset := 2
	// Decode rs
	for i := 0; i < int(arrayLen); i++ {
		copy(rs[i][:], data[offset:offset+32])
		offset += 32
	}
	// Decode ss
	for i := 0; i < int(arrayLen); i++ {
		copy(ss[i][:], data[offset:offset+32])
		offset += 32
	}

	return rs, ss, nil
}
