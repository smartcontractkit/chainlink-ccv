package v1

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"google.golang.org/genproto/googleapis/rpc/status"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	v1 "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

// Exported types wrapping the generated protobuf types. The main purpose is to implement custom
// JSON marshaling/unmarshalling logic while remaining compatible with the generated protobuf types.
// That way we can assure compatibility between gRPC and REST API representations.
// Wrapping is required to implement marshalJSON/unmarshalJSON methods without modifying the generated code.
//
// Additionally, types here are convertible to protocol ones (and back)
// * VerifierResultsResponse -- ToVerifierResults() --> map[protocol.Bytes32]protocol.VerifierResult
// * VerifierResult -- ToVerifierResult() --> protocol.VerifierResult
// * VerifierResult <-- NewVerifierResult() -- protocol.VerifierResult
// * VerifierResultMessage -- ToMessage() -> protocol.VerifierResultMessage
// * VerifierResultMessage <-- NewVerifierResultMessage() -- protocol.VerifierResultMessage

type VerifierResultsResponse struct {
	*v1.GetVerifierResultsForMessageResponse
}

type VerifierResult struct {
	*v1.VerifierResult
}

type VerifierResultsMetadata struct {
	*v1.VerifierResultMetadata
}

type VerifierResultMessage struct {
	*v1.Message
}

// Intermediate types for JSON marshaling/unmarshalling.
// JSON schema of these types must stay aligned with the v1 protobuf definitions - enforced by tests.
// They must not be exported outside of this package, used internally only to simplify JSON (un)marshaling logic.

// verifierResultsResponseJSON represents the JSON structure for VerifierResultsResponse / v1.GetVerifierResultsForMessageResponse.
type verifierResultsResponseJSON struct {
	Results []*VerifierResult `json:"results"`
	Errors  []string          `json:"errors,omitempty"`
}

// verifierResultsJSON represents the JSON structure for VerifierResult / v1.VerifierResult.
type verifierResultsJSON struct {
	Message                *VerifierResultMessage    `json:"message"`
	MessageCcvAddresses    []protocol.UnknownAddress `json:"message_ccv_addresses"`
	MessageExecutorAddress protocol.UnknownAddress   `json:"message_executor_address"`
	CcvData                protocol.ByteSlice        `json:"ccv_data"`
	Metadata               *VerifierResultsMetadata  `json:"metadata,omitempty"`
}

// verifierResultsMetadataJSON represents the JSON structure for VerifierResultsMetadata / v1.VerifierResultMetadata.
type verifierResultsMetadataJSON struct {
	Timestamp             int64                   `json:"timestamp,omitempty"`
	VerifierSourceAddress protocol.UnknownAddress `json:"verifier_source_address,omitempty"`
	VerifierDestAddress   protocol.UnknownAddress `json:"verifier_dest_address,omitempty"`
}

func NewVerifierResultsResponse(
	results []VerifierResult,
	errors []string,
) *VerifierResultsResponse {
	protoResults := make([]*v1.VerifierResult, len(results))
	for i, res := range results {
		protoResults[i] = res.VerifierResult
	}

	protoErrors := make([]*status.Status, len(errors))
	for i, errMsg := range errors {
		protoErrors[i] = &status.Status{
			Message: errMsg,
		}
	}

	return &VerifierResultsResponse{
		&v1.GetVerifierResultsForMessageResponse{
			Results: protoResults,
			Errors:  protoErrors,
		},
	}
}

func (r *VerifierResultsResponse) MarshalJSON() ([]byte, error) {
	if r.GetVerifierResultsForMessageResponse == nil {
		return nil, fmt.Errorf("GetVerifierResultsForMessageResponse is nil")
	}

	results := make([]*VerifierResult, len(r.Results))
	for i, res := range r.Results {
		results[i] = &VerifierResult{res}
	}
	errors := make([]string, len(r.Errors))
	for i, errStatus := range r.Errors {
		errors[i] = errStatus.Message
	}

	return json.Marshal(
		verifierResultsResponseJSON{
			Results: results,
			Errors:  errors,
		})
}

func (r *VerifierResultsResponse) UnmarshalJSON(data []byte) error {
	var aux verifierResultsResponseJSON
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	results := make([]*v1.VerifierResult, len(aux.Results))
	for i, res := range aux.Results {
		results[i] = res.VerifierResult
	}

	errors := make([]*status.Status, len(aux.Errors))
	for i, errMsg := range aux.Errors {
		errors[i] = &status.Status{Message: errMsg}
	}

	r.GetVerifierResultsForMessageResponse = &v1.GetVerifierResultsForMessageResponse{
		Results: results,
		Errors:  errors,
	}
	return nil
}

func (r *VerifierResultsResponse) ToVerifierResults() (map[protocol.Bytes32]protocol.VerifierResult, error) {
	if r.GetVerifierResultsForMessageResponse == nil {
		return nil, fmt.Errorf("GetVerifierResultsForMessageResponse is nil")
	}

	mappedResults := make(map[protocol.Bytes32]protocol.VerifierResult)

	for i, responseResult := range r.Results {
		// Response is nil if message not found in aggregator
		if responseResult == nil {
			continue
		}

		result, err := (&VerifierResult{VerifierResult: responseResult}).ToVerifierResult()
		if err != nil {
			return nil, fmt.Errorf("error mapping message at index %d: %w", i, err)
		}

		messageID, err := result.Message.MessageID()
		if err != nil {
			return nil, fmt.Errorf("error computing message ID at index %d: %w", i, err)
		}
		mappedResults[messageID] = result
	}
	return mappedResults, nil
}

func NewVerifierResult(r protocol.VerifierResult) VerifierResult {
	addresses := make([][]byte, len(r.MessageCCVAddresses))
	for i, addr := range r.MessageCCVAddresses {
		addresses[i] = addr.Bytes()
	}

	message := NewVerifierResultMessage(r.Message)
	return VerifierResult{
		&v1.VerifierResult{
			Message:                message.Message,
			MessageCcvAddresses:    addresses,
			MessageExecutorAddress: r.MessageExecutorAddress,
			CcvData:                r.CCVData,
			Metadata: &v1.VerifierResultMetadata{
				Timestamp:             r.Timestamp.UnixMilli(),
				VerifierSourceAddress: r.VerifierSourceAddress,
				VerifierDestAddress:   r.VerifierDestAddress,
			},
		},
	}
}

func (r *VerifierResult) MarshalJSON() ([]byte, error) {
	if r.VerifierResult == nil {
		return nil, fmt.Errorf("VerifierResult is nil")
	}

	messageCcvAddresses := make([]protocol.UnknownAddress, len(r.MessageCcvAddresses))
	for i, addr := range r.MessageCcvAddresses {
		messageCcvAddresses[i] = addr
	}

	return json.Marshal(
		verifierResultsJSON{
			Message: &VerifierResultMessage{
				Message: r.Message,
			},
			MessageCcvAddresses: messageCcvAddresses,
			MessageExecutorAddress: protocol.UnknownAddress(
				r.MessageExecutorAddress,
			),
			CcvData: protocol.ByteSlice(r.CcvData),
			Metadata: &VerifierResultsMetadata{
				VerifierResultMetadata: r.Metadata,
			},
		})
}

func (r *VerifierResult) UnmarshalJSON(data []byte) error {
	var aux verifierResultsJSON
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.Message == nil {
		return fmt.Errorf("message field is required but was missing")
	}

	messageCcvAddresses := make([][]byte, len(aux.MessageCcvAddresses))
	for i, addr := range aux.MessageCcvAddresses {
		messageCcvAddresses[i] = addr.Bytes()
	}

	r.VerifierResult = &v1.VerifierResult{
		Message:                aux.Message.Message,
		MessageCcvAddresses:    messageCcvAddresses,
		MessageExecutorAddress: aux.MessageExecutorAddress.Bytes(),
		CcvData:                aux.CcvData,
		Metadata:               aux.Metadata.VerifierResultMetadata,
	}
	return nil
}

func (r *VerifierResult) ToVerifierResult() (protocol.VerifierResult, error) {
	if r.VerifierResult == nil {
		return protocol.VerifierResult{}, fmt.Errorf("VerifierResult is nil")
	}

	message, err := (&VerifierResultMessage{Message: r.Message}).ToMessage()
	if err != nil {
		return protocol.VerifierResult{}, fmt.Errorf("failed to convert VerifierResultMessage to Message: %w", err)
	}

	messageID, err := message.MessageID()
	if err != nil {
		return protocol.VerifierResult{}, fmt.Errorf("error computing message ID: %w", err)
	}

	var timestamp time.Time
	var verifierDestAddress protocol.UnknownAddress
	var verifierSourceAddress protocol.UnknownAddress
	if r.Metadata != nil {
		timestamp = time.UnixMilli(r.Metadata.Timestamp)
		verifierDestAddress = r.Metadata.VerifierDestAddress
		verifierSourceAddress = r.Metadata.VerifierSourceAddress
	}

	messageCCVAddresses := make([]protocol.UnknownAddress, len(r.MessageCcvAddresses))
	for i, addr := range r.MessageCcvAddresses {
		messageCCVAddresses[i] = addr
	}

	return protocol.VerifierResult{
		MessageID:              messageID,
		Message:                message,
		MessageCCVAddresses:    messageCCVAddresses,
		MessageExecutorAddress: r.MessageExecutorAddress,
		CCVData:                r.CcvData,
		Timestamp:              timestamp,
		VerifierSourceAddress:  verifierSourceAddress,
		VerifierDestAddress:    verifierDestAddress,
	}, nil
}

func (r *VerifierResultsMetadata) MarshalJSON() ([]byte, error) {
	if r.VerifierResultMetadata == nil {
		return nil, fmt.Errorf("VerifierResultMetadata is nil")
	}

	return json.Marshal(
		verifierResultsMetadataJSON{
			Timestamp:             r.Timestamp,
			VerifierSourceAddress: r.VerifierSourceAddress,
			VerifierDestAddress:   r.VerifierDestAddress,
		},
	)
}

func (r *VerifierResultsMetadata) UnmarshalJSON(data []byte) error {
	var aux verifierResultsMetadataJSON
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	r.VerifierResultMetadata = &v1.VerifierResultMetadata{
		Timestamp:             aux.Timestamp,
		VerifierSourceAddress: aux.VerifierSourceAddress.Bytes(),
		VerifierDestAddress:   aux.VerifierDestAddress.Bytes(),
	}
	return nil
}

func NewVerifierResultMessage(message protocol.Message) VerifierResultMessage {
	var tokenTransferBytes []byte
	if message.TokenTransfer != nil {
		tokenTransferBytes = message.TokenTransfer.Encode()
	}

	return VerifierResultMessage{
		Message: &v1.Message{
			Version:              uint32(message.Version),
			SourceChainSelector:  uint64(message.SourceChainSelector),
			DestChainSelector:    uint64(message.DestChainSelector),
			SequenceNumber:       uint64(message.SequenceNumber),
			OnRampAddress:        message.OnRampAddress.Bytes(),
			OffRampAddress:       message.OffRampAddress.Bytes(),
			Finality:             uint32(message.Finality),
			ExecutionGasLimit:    message.ExecutionGasLimit,
			CcipReceiveGasLimit:  message.CcipReceiveGasLimit,
			CcvAndExecutorHash:   message.CcvAndExecutorHash[:],
			Sender:               message.Sender.Bytes(),
			Receiver:             message.Receiver.Bytes(),
			DestBlob:             message.DestBlob,
			TokenTransfer:        tokenTransferBytes,
			Data:                 message.Data,
			OnRampAddressLength:  uint32(message.OnRampAddressLength),
			OffRampAddressLength: uint32(message.OffRampAddressLength),
			SenderLength:         uint32(message.SenderLength),
			ReceiverLength:       uint32(message.ReceiverLength),
			DestBlobLength:       uint32(message.DestBlobLength),
			DataLength:           uint32(message.DataLength),
			TokenTransferLength:  uint32(message.TokenTransferLength),
		},
	}
}

func (r *VerifierResultMessage) MarshalJSON() ([]byte, error) {
	message, err := r.ToMessage()
	if err != nil {
		return nil, err
	}
	return json.Marshal(message)
}

func (r *VerifierResultMessage) UnmarshalJSON(data []byte) error {
	var aux protocol.Message
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	resultMessage := NewVerifierResultMessage(aux)
	r.Message = resultMessage.Message
	return nil
}

func (r *VerifierResultMessage) ToMessage() (protocol.Message, error) {
	if r.Message == nil {
		return protocol.Message{}, fmt.Errorf("message field is nil")
	}

	ccvAndExecutorHash := protocol.Bytes32{}

	if r.CcvAndExecutorHash != nil {
		ccvAndExecutorHash = protocol.Bytes32(r.CcvAndExecutorHash)
	}

	var tokenTransfer *protocol.TokenTransfer
	if len(r.TokenTransfer) > 0 {
		tt, err := protocol.DecodeTokenTransfer(r.TokenTransfer)
		if err != nil {
			return protocol.Message{}, fmt.Errorf("failed to decode token transfer: %w", err)
		}
		tokenTransfer = tt
	}

	if r.Version > math.MaxUint8 {
		return protocol.Message{}, fmt.Errorf("field Version %d exceeds uint8 max", r.Version)
	}
	if r.OnRampAddressLength > math.MaxUint8 {
		return protocol.Message{}, fmt.Errorf("field OnRampAddressLength %d exceeds uint8 max",
			r.OnRampAddressLength)
	}
	if r.OffRampAddressLength > math.MaxUint8 {
		return protocol.Message{}, fmt.Errorf("field OffRampAddressLength %d exceeds uint8 max",
			r.OffRampAddressLength)
	}
	if r.Finality > math.MaxUint16 {
		return protocol.Message{}, fmt.Errorf("field Finality %d exceeds uint16 max", r.Finality)
	}
	if r.SenderLength > math.MaxUint8 {
		return protocol.Message{}, fmt.Errorf("field SenderLength %d exceeds uint8 max", r.SenderLength)
	}
	if r.ReceiverLength > math.MaxUint8 {
		return protocol.Message{}, fmt.Errorf("field ReceiverLength %d exceeds uint8 max", r.ReceiverLength)
	}
	if r.DestBlobLength > math.MaxUint16 {
		return protocol.Message{}, fmt.Errorf("field DestBlobLength %d exceeds uint16 max", r.DestBlobLength)
	}
	if r.TokenTransferLength > math.MaxUint16 {
		return protocol.Message{}, fmt.Errorf("field TokenTransferLength %d exceeds uint16 max", r.TokenTransferLength)
	}
	if r.DataLength > math.MaxUint16 {
		return protocol.Message{}, fmt.Errorf("field DataLength %d exceeds uint16 max", r.DataLength)
	}

	return protocol.Message{
		//nolint:gosec // data length verified at this stage
		Version:             uint8(r.Version),
		SourceChainSelector: protocol.ChainSelector(r.SourceChainSelector),
		DestChainSelector:   protocol.ChainSelector(r.DestChainSelector),
		SequenceNumber:      protocol.SequenceNumber(r.SequenceNumber),
		OnRampAddress:       r.OnRampAddress,
		OffRampAddress:      r.OffRampAddress,
		ExecutionGasLimit:   r.ExecutionGasLimit,
		CcipReceiveGasLimit: r.CcipReceiveGasLimit,
		CcvAndExecutorHash:  ccvAndExecutorHash,
		Sender:              r.Sender,
		Receiver:            r.Receiver,
		DestBlob:            r.DestBlob,
		TokenTransfer:       tokenTransfer,
		Data:                r.Data,
		//nolint:gosec // data length verified at this stage
		OnRampAddressLength: uint8(r.OnRampAddressLength),
		//nolint:gosec // data length verified at this stage
		OffRampAddressLength: uint8(r.OffRampAddressLength),
		//nolint:gosec // data length verified at this stage
		Finality: uint16(r.Finality),
		//nolint:gosec // data length verified at this stage
		SenderLength: uint8(r.SenderLength),
		//nolint:gosec // data length verified at this stage
		ReceiverLength: uint8(r.ReceiverLength),
		//nolint:gosec // data length verified at this stage
		DestBlobLength: uint16(r.DestBlobLength),
		//nolint:gosec // data length verified at this stage
		TokenTransferLength: uint16(r.TokenTransferLength),
		//nolint:gosec // data length verified at this stage
		DataLength: uint16(r.DataLength),
	}, nil
}
