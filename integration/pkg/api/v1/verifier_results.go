package v1

import (
	"encoding/json"

	"google.golang.org/genproto/googleapis/rpc/status"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	v1 "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// Exported types wrapping the generated protobuf types. The main purpose is to implement custom
// JSON marshaling/unmarshalling logic while remaining compatible with the generated protobuf types.
// That way we can assure compatibility between gRPC and REST API representations.
// Wrapping is required to implement marshalJSON/unmarshalJSON methods without modifying the generated code.

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

func NewVerifierResult(r protocol.VerifierResult) VerifierResult {
	addresses := make([][]byte, len(r.MessageCCVAddresses))
	for i, addr := range r.MessageCCVAddresses {
		addresses[i] = addr.Bytes()
	}
	tokenTransferBytes := protocol.ByteSlice{}
	if r.Message.TokenTransfer != nil {
		tokenTransferBytes = r.Message.TokenTransfer.Encode()
	}

	return VerifierResult{
		&v1.VerifierResult{
			Message: &v1.Message{
				Version:             uint32(r.Message.Version),
				SourceChainSelector: uint64(r.Message.SourceChainSelector),
				DestChainSelector:   uint64(r.Message.DestChainSelector),
				SequenceNumber:      uint64(r.Message.SequenceNumber),
				OnRampAddress:       r.Message.OnRampAddress.Bytes(),
				OffRampAddress:      r.Message.OffRampAddress.Bytes(),
				Finality:            uint32(r.Message.Finality),
				ExecutionGasLimit:   r.Message.ExecutionGasLimit,
				CcipReceiveGasLimit: r.Message.CcipReceiveGasLimit,
				CcvAndExecutorHash:  r.Message.CcvAndExecutorHash[:],
				Sender:              r.Message.Sender.Bytes(),
				Receiver:            r.Message.Receiver.Bytes(),
				DestBlob:            r.Message.DestBlob,
				TokenTransfer:       tokenTransferBytes,
				Data:                r.Message.Data,
			},
			MessageCcvAddresses:    addresses,
			MessageExecutorAddress: r.MessageExecutorAddress,
			CcvData:                r.CCVData,
			Metadata: &v1.VerifierResultMetadata{
				Timestamp:             r.Timestamp.Unix(),
				VerifierSourceAddress: r.VerifierSourceAddress,
				VerifierDestAddress:   r.VerifierDestAddress,
			},
		},
	}
}

func (r *VerifierResult) MarshalJSON() ([]byte, error) {
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

	messageCcvAddresses := make([][]byte, len(aux.MessageCcvAddresses))
	for i, addr := range aux.MessageCcvAddresses {
		messageCcvAddresses[i] = addr.Bytes()
	}

	r.VerifierResult = &v1.VerifierResult{
		Message:                aux.Message.Message,
		MessageCcvAddresses:    messageCcvAddresses,
		MessageExecutorAddress: aux.MessageExecutorAddress.Bytes(),
		CcvData:                aux.CcvData,
		Metadata: &v1.VerifierResultMetadata{
			Timestamp:             aux.Metadata.Timestamp,
			VerifierSourceAddress: aux.Metadata.VerifierSourceAddress,
			VerifierDestAddress:   aux.Metadata.VerifierDestAddress,
		},
	}
	return nil
}

func (r *VerifierResultsMetadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		verifierResultsMetadataJSON{
			Timestamp:             r.Timestamp,
			VerifierSourceAddress: protocol.UnknownAddress(r.VerifierSourceAddress),
			VerifierDestAddress:   protocol.UnknownAddress(r.VerifierDestAddress),
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

func (r *VerifierResultMessage) MarshalJSON() ([]byte, error) {
	ccvAndExecutorHash := protocol.Bytes32{}
	if r.CcvAndExecutorHash != nil {
		ccvAndExecutorHash = protocol.Bytes32(r.CcvAndExecutorHash)
	}

	var tokenTransfer *protocol.TokenTransfer
	if len(r.TokenTransfer) > 0 {
		tt, err := protocol.DecodeTokenTransfer(protocol.ByteSlice(r.TokenTransfer))
		if err != nil {
			return nil, err
		}
		tokenTransfer = tt
	}

	return json.Marshal(
		protocol.Message{
			//nolint:gosec // proto types use uint32 for Version, but we want uint8 in JSON
			Version:             uint8(r.Version),
			SourceChainSelector: protocol.ChainSelector(r.SourceChainSelector),
			DestChainSelector:   protocol.ChainSelector(r.DestChainSelector),
			SequenceNumber:      protocol.SequenceNumber(r.SequenceNumber),
			OnRampAddress:       r.OnRampAddress,
			OffRampAddress:      protocol.UnknownAddress(r.OffRampAddress),
			//nolint:gosec // proto types use uint32 for Finality, but we want uint16 in JSON
			Finality:            uint16(r.Finality),
			ExecutionGasLimit:   r.ExecutionGasLimit,
			CcipReceiveGasLimit: r.CcipReceiveGasLimit,
			CcvAndExecutorHash:  ccvAndExecutorHash,
			Sender:              protocol.UnknownAddress(r.Sender),
			Receiver:            protocol.UnknownAddress(r.Receiver),
			DestBlob:            protocol.ByteSlice(r.DestBlob),
			TokenTransfer:       tokenTransfer,
			Data:                protocol.ByteSlice(r.Data),
		},
	)
}

func (r *VerifierResultMessage) UnmarshalJSON(data []byte) error {
	var aux protocol.Message
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	var tokenTransferBytes []byte
	if aux.TokenTransfer != nil {
		tokenTransferBytes = aux.TokenTransfer.Encode()
	}

	r.Message = &v1.Message{
		Version:             uint32(aux.Version),
		SourceChainSelector: uint64(aux.SourceChainSelector),
		DestChainSelector:   uint64(aux.DestChainSelector),
		SequenceNumber:      uint64(aux.SequenceNumber),
		OnRampAddress:       aux.OnRampAddress.Bytes(),
		OffRampAddress:      aux.OffRampAddress.Bytes(),
		Finality:            uint32(aux.Finality),
		ExecutionGasLimit:   aux.ExecutionGasLimit,
		CcipReceiveGasLimit: aux.CcipReceiveGasLimit,
		CcvAndExecutorHash:  aux.CcvAndExecutorHash[:],
		Sender:              aux.Sender.Bytes(),
		Receiver:            aux.Receiver.Bytes(),
		DestBlob:            aux.DestBlob,
		TokenTransfer:       tokenTransferBytes,
		Data:                aux.Data,
	}
	return nil
}
