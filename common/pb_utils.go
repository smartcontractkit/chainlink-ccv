package common

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

func MapProtoMessageToProtocolMessage(m *verifierpb.Message) (*protocol.Message, error) {
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

// MapProtocolMessageToProtoMessage converts a protocol.Message to verifierpb.Message.
func MapProtocolMessageToProtoMessage(m *protocol.Message) *verifierpb.Message {
	var tokenTransferBytes []byte
	if m.TokenTransfer != nil {
		tokenTransferBytes = m.TokenTransfer.Encode()
	}

	return &verifierpb.Message{
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
