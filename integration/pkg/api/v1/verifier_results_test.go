package v1

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	v1 "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func TestVerifierResultsMetadata_RoundTrip(t *testing.T) {
	tests := []struct {
		name         string
		metadata     *VerifierResultsMetadata
		expectedJSON string
	}{
		{
			name: "with all fields populated",
			metadata: &VerifierResultsMetadata{
				VerifierResultMetadata: &v1.VerifierResultMetadata{
					Timestamp:             1234567890,
					VerifierSourceAddress: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
					VerifierDestAddress:   []byte{0x06, 0x07, 0x08, 0x09, 0x0a},
				},
			},
			expectedJSON: `{
				"timestamp": 1234567890,
				"verifier_source_address": "0x0102030405",
				"verifier_dest_address": "0x060708090a"
			}`,
		},
		{
			name: "with empty addresses",
			metadata: &VerifierResultsMetadata{
				VerifierResultMetadata: &v1.VerifierResultMetadata{
					Timestamp:             9876543210,
					VerifierSourceAddress: nil,
					VerifierDestAddress:   nil,
				},
			},
			expectedJSON: `{
				"timestamp": 9876543210
			}`,
		},
		{
			name: "with 20-byte addresses",
			metadata: &VerifierResultsMetadata{
				VerifierResultMetadata: &v1.VerifierResultMetadata{
					Timestamp:             1111111111,
					VerifierSourceAddress: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
					VerifierDestAddress:   []byte{0x14, 0x13, 0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01},
				},
			},
			expectedJSON: `{
				"timestamp": 1111111111,
				"verifier_source_address": "0x0102030405060708090a0b0c0d0e0f1011121314",
				"verifier_dest_address": "0x14131211100f0e0d0c0b0a090807060504030201"
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Marshal to JSON
			jsonData, err := json.Marshal(tt.metadata)
			require.NoError(t, err)

			// Step 2: Compare with expected JSON
			assert.JSONEq(t, tt.expectedJSON, string(jsonData), "serialized JSON should match expected JSON")

			// Step 3: Unmarshal back
			var got VerifierResultsMetadata
			err = json.Unmarshal(jsonData, &got)
			require.NoError(t, err)

			// Step 4: Verify round-trip preserved data
			assert.Equal(t, tt.metadata.Timestamp, got.Timestamp)
			assert.Equal(t, tt.metadata.VerifierSourceAddress, got.VerifierSourceAddress)
			assert.Equal(t, tt.metadata.VerifierDestAddress, got.VerifierDestAddress)
		})
	}

	t.Run("with invalid addresses", func(t *testing.T) {
		malformedJSON := `{
			"timestamp": 1234567890,
			"verifier_source_address": "0xGGGG",
			"verifier_dest_address": "0x040506"
		}`

		var metadata VerifierResultsMetadata
		err := json.Unmarshal([]byte(malformedJSON), &metadata)

		require.Error(t, err)
		require.ErrorContains(t, err, "failed to decode hex")
	})
}

func TestVerifierResultsMetadata_SchemaCompatibility(t *testing.T) {
	t.Run("bidirectional serialization produces equivalent results", func(t *testing.T) {
		// Create original proto metadata
		original := &v1.VerifierResultMetadata{
			Timestamp:             1234567890,
			VerifierSourceAddress: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			VerifierDestAddress:   []byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e},
		}

		// PATH 1: JSON serialization -> deserialization
		customWrapper := &VerifierResultsMetadata{VerifierResultMetadata: original}
		customJSON, err := json.Marshal(customWrapper)
		require.NoError(t, err)

		var jsonDeserialized VerifierResultsMetadata
		err = json.Unmarshal(customJSON, &jsonDeserialized)
		require.NoError(t, err)

		// PATH 2: Proto JSON serialization -> deserialization
		protoJSON, err := protojson.Marshal(original)
		require.NoError(t, err)

		var protoDeserialized v1.VerifierResultMetadata
		err = protojson.Unmarshal(protoJSON, &protoDeserialized)
		require.NoError(t, err)

		// Compare results from both paths
		assert.Equal(t, original.Timestamp, jsonDeserialized.Timestamp, "timestamps should match")
		assert.Equal(t, original.Timestamp, protoDeserialized.Timestamp, "timestamps should match")

		assert.Equal(t, original.VerifierSourceAddress, jsonDeserialized.VerifierSourceAddress, "source addresses should match")
		assert.Equal(t, original.VerifierSourceAddress, protoDeserialized.VerifierSourceAddress, "source addresses should match")

		assert.Equal(t, original.VerifierDestAddress, jsonDeserialized.VerifierDestAddress, "dest addresses should match")
		assert.Equal(t, original.VerifierDestAddress, protoDeserialized.VerifierDestAddress, "dest addresses should match")

		// Verify both deserialized objects are equivalent to original
		assert.Equal(t, original.Timestamp, jsonDeserialized.Timestamp)
		assert.Equal(t, original.VerifierSourceAddress, jsonDeserialized.VerifierSourceAddress)
		assert.Equal(t, original.VerifierDestAddress, jsonDeserialized.VerifierDestAddress)

		assert.Equal(t, original.Timestamp, protoDeserialized.Timestamp)
		assert.Equal(t, original.VerifierSourceAddress, protoDeserialized.VerifierSourceAddress)
		assert.Equal(t, original.VerifierDestAddress, protoDeserialized.VerifierDestAddress)
	})

	t.Run("round-trip through both formats produces equivalent results", func(t *testing.T) {
		// Original data
		original := &v1.VerifierResultMetadata{
			Timestamp:             1111111111,
			VerifierSourceAddress: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
			VerifierDestAddress:   []byte{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		}

		// Round-trip through custom JSON
		customWrapper1 := &VerifierResultsMetadata{VerifierResultMetadata: original}
		customJSON1, err := json.Marshal(customWrapper1)
		require.NoError(t, err)

		var customRoundTrip VerifierResultsMetadata
		err = json.Unmarshal(customJSON1, &customRoundTrip)
		require.NoError(t, err)

		// Serialize again to verify stability
		customJSON2, err := json.Marshal(&customRoundTrip)
		require.NoError(t, err)
		assert.JSONEq(t, string(customJSON1), string(customJSON2), "custom JSON should be stable through round-trip")

		// Round-trip through proto JSON
		protoJSON1, err := protojson.Marshal(original)
		require.NoError(t, err)

		var protoRoundTrip v1.VerifierResultMetadata
		err = protojson.Unmarshal(protoJSON1, &protoRoundTrip)
		require.NoError(t, err)

		// Serialize again to verify stability
		protoJSON2, err := protojson.Marshal(&protoRoundTrip)
		require.NoError(t, err)
		assert.JSONEq(t, string(protoJSON1), string(protoJSON2), "proto JSON should be stable through round-trip")

		// Verify both round-trips preserved the data correctly
		assert.Equal(t, original.Timestamp, customRoundTrip.Timestamp)
		assert.Equal(t, original.VerifierSourceAddress, customRoundTrip.VerifierSourceAddress)
		assert.Equal(t, original.VerifierDestAddress, customRoundTrip.VerifierDestAddress)

		assert.Equal(t, original.Timestamp, protoRoundTrip.Timestamp)
		assert.Equal(t, original.VerifierSourceAddress, protoRoundTrip.VerifierSourceAddress)
		assert.Equal(t, original.VerifierDestAddress, protoRoundTrip.VerifierDestAddress)

		// Results from both paths should be equivalent
		assert.Equal(t, customRoundTrip.Timestamp, protoRoundTrip.Timestamp)
		assert.Equal(t, customRoundTrip.VerifierSourceAddress, protoRoundTrip.VerifierSourceAddress)
		assert.Equal(t, customRoundTrip.VerifierDestAddress, protoRoundTrip.VerifierDestAddress)
	})
}

func TestVerifierResultsResponse_RoundTrip(t *testing.T) {
	tests := []struct {
		name         string
		response     *VerifierResultsResponse
		expectedJSON string
	}{
		{
			name: "with single result and no errors",
			response: &VerifierResultsResponse{
				GetVerifierResultsForMessageResponse: &v1.GetVerifierResultsForMessageResponse{
					Results: []*v1.VerifierResult{
						{
							Message: &v1.Message{
								Version:             1,
								SourceChainSelector: 100,
								DestChainSelector:   200,
								SequenceNumber:      42,
								OnRampAddress:       []byte{0x01, 0x02, 0x03},
								OffRampAddress:      []byte{0x04, 0x05, 0x06},
								Finality:            10,
								ExecutionGasLimit:   200000,
								CcipReceiveGasLimit: 150000,
								CcvAndExecutorHash:  make([]byte, 32),
								Sender:              []byte{0x07, 0x08, 0x09},
								Receiver:            []byte{0x0a, 0x0b, 0x0c},
								DestBlob:            []byte{0x0d, 0x0e},
								TokenTransfer:       nil,
								Data:                []byte{0x10, 0x11},
							},
							MessageCcvAddresses:    [][]byte{{0x13, 0x14, 0x15}},
							MessageExecutorAddress: []byte{0x16, 0x17, 0x18},
							CcvData:                []byte{0x19, 0x1a, 0x1b},
							Metadata: &v1.VerifierResultMetadata{
								Timestamp:             1234567890,
								VerifierSourceAddress: []byte{0xa1, 0xa2},
								VerifierDestAddress:   []byte{0xb1, 0xb2},
							},
						},
					},
					Errors: nil,
				},
			},
			expectedJSON: `{
				"results": [{
					"message": {
						"version": 1,
						"source_chain_selector": 100,
						"dest_chain_selector": 200,
						"sequence_number": 42,
						"on_ramp_address": "0x010203",
						"on_ramp_address_length": 0,
						"off_ramp_address": "0x040506",
						"off_ramp_address_length": 0,
						"finality": 10,
						"execution_gas_limit": 200000,
						"ccip_receive_gas_limit": 150000,
						"ccv_and_executor_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
						"sender": "0x070809",
						"sender_length": 0,
						"receiver": "0x0a0b0c",
						"receiver_length": 0,
						"dest_blob": "0x0d0e",
						"dest_blob_length": 0,
						"token_transfer": null,
						"token_transfer_length": 0,
						"data": "0x1011",
						"data_length": 0
					},
					"message_ccv_addresses": ["0x131415"],
					"message_executor_address": "0x161718",
					"ccv_data": "0x191a1b",
					"metadata": {
						"timestamp": 1234567890,
						"verifier_source_address": "0xa1a2",
						"verifier_dest_address": "0xb1b2"
					}
				}]
			}`,
		},
		{
			name: "with multiple results and errors",
			response: &VerifierResultsResponse{
				GetVerifierResultsForMessageResponse: &v1.GetVerifierResultsForMessageResponse{
					Results: []*v1.VerifierResult{
						{
							Message: &v1.Message{
								Version:             1,
								SourceChainSelector: 1,
								DestChainSelector:   2,
								SequenceNumber:      10,
								OnRampAddress:       []byte{0x01},
								OffRampAddress:      []byte{0x02},
								Finality:            5,
								ExecutionGasLimit:   100000,
								CcipReceiveGasLimit: 50000,
								CcvAndExecutorHash:  make([]byte, 32),
								Sender:              []byte{0x03},
								Receiver:            []byte{0x04},
								DestBlob:            []byte{},
								TokenTransfer:       nil,
								Data:                []byte{},
							},
							MessageCcvAddresses:    [][]byte{{0x05}},
							MessageExecutorAddress: []byte{0x06},
							CcvData:                []byte{0x07},
							Metadata: &v1.VerifierResultMetadata{
								Timestamp:             9999999999,
								VerifierSourceAddress: []byte{0x11},
								VerifierDestAddress:   []byte{0x22},
							},
						},
						{
							Message: &v1.Message{
								Version:             2,
								SourceChainSelector: 3,
								DestChainSelector:   4,
								SequenceNumber:      20,
								OnRampAddress:       []byte{0xaa},
								OffRampAddress:      []byte{0xbb},
								Finality:            15,
								ExecutionGasLimit:   300000,
								CcipReceiveGasLimit: 250000,
								CcvAndExecutorHash:  make([]byte, 32),
								Sender:              []byte{0xcc},
								Receiver:            []byte{0xdd},
								DestBlob:            []byte{},
								TokenTransfer:       nil,
								Data:                []byte{},
							},
							MessageCcvAddresses:    [][]byte{{0xee}},
							MessageExecutorAddress: []byte{0xff},
							CcvData:                []byte{0x99},
							Metadata: &v1.VerifierResultMetadata{
								Timestamp:             8888888888,
								VerifierSourceAddress: []byte{0x33},
								VerifierDestAddress:   []byte{0x44},
							},
						},
					},
					Errors: []*status.Status{
						{Message: "error message 1"},
						{Message: "error message 2"},
					},
				},
			},
			expectedJSON: `{
				"results": [
					{
						"message": {
							"version": 1,
							"source_chain_selector": 1,
							"dest_chain_selector": 2,
							"sequence_number": 10,
							"on_ramp_address": "0x01",
							"on_ramp_address_length": 0,
							"off_ramp_address": "0x02",
							"off_ramp_address_length": 0,
							"finality": 5,
							"execution_gas_limit": 100000,
							"ccip_receive_gas_limit": 50000,
							"ccv_and_executor_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
							"sender": "0x03",
							"sender_length": 0,
							"receiver": "0x04",
							"receiver_length": 0,
							"dest_blob": "0x",
							"dest_blob_length": 0,
							"token_transfer": null,
							"token_transfer_length": 0,
							"data": "0x",
							"data_length": 0
						},
						"message_ccv_addresses": ["0x05"],
						"message_executor_address": "0x06",
						"ccv_data": "0x07",
						"metadata": {
							"timestamp": 9999999999,
							"verifier_source_address": "0x11",
							"verifier_dest_address": "0x22"
						}
					},
					{
						"message": {
							"version": 2,
							"source_chain_selector": 3,
							"dest_chain_selector": 4,
							"sequence_number": 20,
							"on_ramp_address": "0xaa",
							"on_ramp_address_length": 0,
							"off_ramp_address": "0xbb",
							"off_ramp_address_length": 0,
							"finality": 15,
							"execution_gas_limit": 300000,
							"ccip_receive_gas_limit": 250000,
							"ccv_and_executor_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
							"sender": "0xcc",
							"sender_length": 0,
							"receiver": "0xdd",
							"receiver_length": 0,
							"dest_blob": "0x",
							"dest_blob_length": 0,
							"token_transfer": null,
							"token_transfer_length": 0,
							"data": "0x",
							"data_length": 0
						},
						"message_ccv_addresses": ["0xee"],
						"message_executor_address": "0xff",
						"ccv_data": "0x99",
						"metadata": {
							"timestamp": 8888888888,
							"verifier_source_address": "0x33",
							"verifier_dest_address": "0x44"
						}
					}
				],
				"errors": ["error message 1", "error message 2"]
			}`,
		},
		{
			name: "with empty results and errors",
			response: &VerifierResultsResponse{
				GetVerifierResultsForMessageResponse: &v1.GetVerifierResultsForMessageResponse{
					Results: []*v1.VerifierResult{},
					Errors:  []*status.Status{},
				},
			},
			expectedJSON: `{
				"results": []
			}`,
		},
		{
			name: "with no results but with errors",
			response: &VerifierResultsResponse{
				GetVerifierResultsForMessageResponse: &v1.GetVerifierResultsForMessageResponse{
					Results: []*v1.VerifierResult{},
					Errors: []*status.Status{
						{Message: "message not found"},
					},
				},
			},
			expectedJSON: `{
				"results": [],
				"errors": ["message not found"]
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Marshal to JSON
			jsonData, err := json.Marshal(tt.response)
			require.NoError(t, err)

			// Step 2: Compare with expected JSON
			assert.JSONEq(t, tt.expectedJSON, string(jsonData), "serialized JSON should match expected JSON")

			// Step 3: Unmarshal back
			var got VerifierResultsResponse
			err = json.Unmarshal(jsonData, &got)
			require.NoError(t, err)

			// Step 4: Verify round-trip preserved data
			assert.Len(t, got.Results, len(tt.response.Results))
			assert.Len(t, got.Errors, len(tt.response.Errors))

			for i, result := range tt.response.Results {
				assert.Equal(t, result.Message.Version, got.Results[i].Message.Version)
				assert.Equal(t, result.Message.SourceChainSelector, got.Results[i].Message.SourceChainSelector)
				assert.Equal(t, result.Message.DestChainSelector, got.Results[i].Message.DestChainSelector)
				assert.Equal(t, result.Message.SequenceNumber, got.Results[i].Message.SequenceNumber)
				assert.Equal(t, result.Message.OnRampAddress, got.Results[i].Message.OnRampAddress)
				assert.Equal(t, result.MessageCcvAddresses, got.Results[i].MessageCcvAddresses)
				assert.Equal(t, result.MessageExecutorAddress, got.Results[i].MessageExecutorAddress)
				assert.Equal(t, result.CcvData, got.Results[i].CcvData)
				assert.Equal(t, result.Metadata.Timestamp, got.Results[i].Metadata.Timestamp)
			}

			for i, errStatus := range tt.response.Errors {
				assert.Equal(t, errStatus.Message, got.Errors[i].Message)
			}
		})
	}

	t.Run("with malformed JSON", func(t *testing.T) {
		malformedJSON := `{
			"results": [{
				"message": {
					"version": 1,
					"source_chain_selector": 100,
					"on_ramp_address": "0xGGGG"
				}
			}]
		}`

		var response VerifierResultsResponse
		err := json.Unmarshal([]byte(malformedJSON), &response)

		require.Error(t, err)
		require.ErrorContains(t, err, "failed to decode hex")
	})
}

func TestVerifierResultsResponse_SchemaCompatibility(t *testing.T) {
	t.Run("bidirectional serialization produces equivalent results", func(t *testing.T) {
		// Create original proto response
		original := &v1.GetVerifierResultsForMessageResponse{
			Results: []*v1.VerifierResult{
				{
					Message: &v1.Message{
						Version:             1,
						SourceChainSelector: 100,
						DestChainSelector:   200,
						SequenceNumber:      42,
						OnRampAddress:       []byte{0x01, 0x02, 0x03},
						OffRampAddress:      []byte{0x04, 0x05, 0x06},
						Finality:            10,
						ExecutionGasLimit:   200000,
						CcipReceiveGasLimit: 150000,
						CcvAndExecutorHash:  make([]byte, 32),
						Sender:              []byte{0x07, 0x08, 0x09},
						Receiver:            []byte{0x0a, 0x0b, 0x0c},
						DestBlob:            []byte{0x0d, 0x0e},
						TokenTransfer:       nil,
						Data:                []byte{0x10, 0x11},
					},
					MessageCcvAddresses:    [][]byte{{0x13, 0x14, 0x15}},
					MessageExecutorAddress: []byte{0x16, 0x17, 0x18},
					CcvData:                []byte{0x19, 0x1a, 0x1b},
					Metadata: &v1.VerifierResultMetadata{
						Timestamp:             1234567890,
						VerifierSourceAddress: []byte{0xa1, 0xa2},
						VerifierDestAddress:   []byte{0xb1, 0xb2},
					},
				},
			},
			Errors: []*status.Status{
				{Message: "test error"},
			},
		}

		// PATH 1: JSON serialization -> deserialization
		customWrapper := &VerifierResultsResponse{GetVerifierResultsForMessageResponse: original}
		customJSON, err := json.Marshal(customWrapper)
		require.NoError(t, err)

		var jsonDeserialized VerifierResultsResponse
		err = json.Unmarshal(customJSON, &jsonDeserialized)
		require.NoError(t, err)

		// PATH 2: Proto JSON serialization -> deserialization
		protoJSON, err := protojson.Marshal(original)
		require.NoError(t, err)

		var protoDeserialized v1.GetVerifierResultsForMessageResponse
		err = protojson.Unmarshal(protoJSON, &protoDeserialized)
		require.NoError(t, err)

		// Compare results from both paths
		assert.Len(t, jsonDeserialized.Results, len(original.Results), "results length should match")
		assert.Len(t, protoDeserialized.Results, len(original.Results), "results length should match")
		assert.Len(t, jsonDeserialized.Errors, len(original.Errors), "errors length should match")
		assert.Len(t, protoDeserialized.Errors, len(original.Errors), "errors length should match")

		// Verify first result
		assert.Equal(t, original.Results[0].Message.Version, jsonDeserialized.Results[0].Message.Version)
		assert.Equal(t, original.Results[0].Message.SourceChainSelector, jsonDeserialized.Results[0].Message.SourceChainSelector)
		assert.Equal(t, original.Results[0].MessageCcvAddresses, jsonDeserialized.Results[0].MessageCcvAddresses)
		assert.Equal(t, original.Results[0].MessageExecutorAddress, jsonDeserialized.Results[0].MessageExecutorAddress)
		assert.Equal(t, original.Results[0].CcvData, jsonDeserialized.Results[0].CcvData)

		assert.Equal(t, original.Results[0].Message.Version, protoDeserialized.Results[0].Message.Version)
		assert.Equal(t, original.Results[0].Message.SourceChainSelector, protoDeserialized.Results[0].Message.SourceChainSelector)
		assert.Equal(t, original.Results[0].MessageCcvAddresses, protoDeserialized.Results[0].MessageCcvAddresses)

		// Verify errors
		assert.Equal(t, original.Errors[0].Message, jsonDeserialized.Errors[0].Message)
		assert.Equal(t, original.Errors[0].Message, protoDeserialized.Errors[0].Message)
	})

	t.Run("round-trip through both formats produces equivalent results", func(t *testing.T) {
		// Original data
		original := &v1.GetVerifierResultsForMessageResponse{
			Results: []*v1.VerifierResult{
				{
					Message: &v1.Message{
						Version:             2,
						SourceChainSelector: 1000,
						DestChainSelector:   2000,
						SequenceNumber:      999,
						OnRampAddress:       []byte{0xaa, 0xbb, 0xcc, 0xdd},
						OffRampAddress:      []byte{0x11, 0x22, 0x33, 0x44},
						Finality:            20,
						ExecutionGasLimit:   500000,
						CcipReceiveGasLimit: 450000,
						CcvAndExecutorHash:  make([]byte, 32),
						Sender:              []byte{0x55, 0x66, 0x77},
						Receiver:            []byte{0x88, 0x99, 0xaa},
						DestBlob:            []byte{0xbb, 0xcc},
						TokenTransfer:       nil,
						Data:                []byte{0xdd, 0xee, 0xff},
					},
					MessageCcvAddresses:    [][]byte{{0x01, 0x02}, {0x03, 0x04}},
					MessageExecutorAddress: []byte{0x05, 0x06, 0x07},
					CcvData:                []byte{0x08, 0x09, 0x0a},
					Metadata: &v1.VerifierResultMetadata{
						Timestamp:             1111222333,
						VerifierSourceAddress: []byte{0xf1, 0xf2, 0xf3},
						VerifierDestAddress:   []byte{0xf4, 0xf5, 0xf6},
					},
				},
			},
			Errors: []*status.Status{
				{Message: "validation error"},
			},
		}

		// Round-trip through custom JSON
		customWrapper1 := &VerifierResultsResponse{GetVerifierResultsForMessageResponse: original}
		customJSON1, err := json.Marshal(customWrapper1)
		require.NoError(t, err)

		var customRoundTrip VerifierResultsResponse
		err = json.Unmarshal(customJSON1, &customRoundTrip)
		require.NoError(t, err)

		// Serialize again to verify stability
		customJSON2, err := json.Marshal(&customRoundTrip)
		require.NoError(t, err)
		assert.JSONEq(t, string(customJSON1), string(customJSON2), "custom JSON should be stable through round-trip")

		// Round-trip through proto JSON
		protoJSON1, err := protojson.Marshal(original)
		require.NoError(t, err)

		var protoRoundTrip v1.GetVerifierResultsForMessageResponse
		err = protojson.Unmarshal(protoJSON1, &protoRoundTrip)
		require.NoError(t, err)

		// Serialize again to verify stability
		protoJSON2, err := protojson.Marshal(&protoRoundTrip)
		require.NoError(t, err)
		assert.JSONEq(t, string(protoJSON1), string(protoJSON2), "proto JSON should be stable through round-trip")

		// Verify both round-trips preserved the data correctly
		assert.Len(t, customRoundTrip.Results, len(original.Results))
		assert.Equal(t, original.Results[0].Message.SourceChainSelector, customRoundTrip.Results[0].Message.SourceChainSelector)
		assert.Equal(t, original.Results[0].Message.DestChainSelector, customRoundTrip.Results[0].Message.DestChainSelector)
		assert.Equal(t, original.Results[0].MessageCcvAddresses, customRoundTrip.Results[0].MessageCcvAddresses)
		assert.Equal(t, original.Errors[0].Message, customRoundTrip.Errors[0].Message)

		assert.Len(t, protoRoundTrip.Results, len(original.Results))
		assert.Equal(t, original.Results[0].Message.SourceChainSelector, protoRoundTrip.Results[0].Message.SourceChainSelector)
		assert.Equal(t, original.Results[0].Message.DestChainSelector, protoRoundTrip.Results[0].Message.DestChainSelector)
		assert.Equal(t, original.Results[0].MessageCcvAddresses, protoRoundTrip.Results[0].MessageCcvAddresses)
		assert.Equal(t, original.Errors[0].Message, protoRoundTrip.Errors[0].Message)

		// Results from both paths should be equivalent
		assert.Equal(t, customRoundTrip.Results[0].Message.Version, protoRoundTrip.Results[0].Message.Version)
		assert.Equal(t, customRoundTrip.Results[0].Message.SequenceNumber, protoRoundTrip.Results[0].Message.SequenceNumber)
		assert.Equal(t, customRoundTrip.Errors[0].Message, protoRoundTrip.Errors[0].Message)
	})
}

func TestVerifierResultMessage_RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		message *protocol.Message
	}{
		{
			name:    "comprehensive message with all fields",
			message: createComprehensiveMessage(t),
		},
		{
			name:    "message without token transfer",
			message: createMessageWithoutTokenTransfer(t),
		},
		{
			name:    "message with minimal fields",
			message: createMinimalMessage(t),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Get original message ID
			originalID, err := tt.message.MessageID()
			require.NoError(t, err)

			// Step 2: Convert protocol.Message to VerifierResultMessage
			verifierResultMsg := NewVerifierResultMessage(*tt.message)
			require.NotNil(t, verifierResultMsg.Message)

			// Step 3: Convert back to protocol.Message
			convertedMessage, err := verifierResultMsg.ToMessage()
			require.NoError(t, err)

			// Step 4: Get converted message ID
			convertedID, err := convertedMessage.MessageID()
			require.NoError(t, err)

			assert.Equal(t, originalID, convertedID)
			assertProtocolMessagesEqual(t, tt.message, &convertedMessage)
		})
	}
}

func createComprehensiveMessage(t *testing.T) *protocol.Message {
	t.Helper()

	sender, err := protocol.RandomAddress()
	require.NoError(t, err)
	receiver, err := protocol.RandomAddress()
	require.NoError(t, err)
	onRamp, err := protocol.RandomAddress()
	require.NoError(t, err)
	offRamp, err := protocol.RandomAddress()
	require.NoError(t, err)

	tokenTransfer := &protocol.TokenTransfer{
		Version:                  protocol.MessageVersion,
		Amount:                   big.NewInt(1000000),
		SourcePoolAddressLength:  20,
		SourcePoolAddress:        make([]byte, 20),
		SourceTokenAddressLength: 20,
		SourceTokenAddress:       make([]byte, 20),
		DestTokenAddressLength:   20,
		DestTokenAddress:         make([]byte, 20),
		TokenReceiverLength:      20,
		TokenReceiver:            make([]byte, 20),
		ExtraDataLength:          10,
		ExtraData:                []byte("extra_data"),
	}

	for i := range tokenTransfer.SourcePoolAddress {
		tokenTransfer.SourcePoolAddress[i] = byte(i + 1)
	}
	for i := range tokenTransfer.SourceTokenAddress {
		tokenTransfer.SourceTokenAddress[i] = byte(i + 21)
	}
	for i := range tokenTransfer.DestTokenAddress {
		tokenTransfer.DestTokenAddress[i] = byte(i + 50)
	}
	for i := range tokenTransfer.TokenReceiver {
		tokenTransfer.TokenReceiver[i] = byte(i + 100)
	}

	destBlob := make([]byte, 50)
	for i := range destBlob {
		destBlob[i] = byte(i + 200)
	}

	messageData := make([]byte, 100)
	for i := range messageData {
		messageData[i] = byte(i + 150)
	}

	ccvAndExecutorHash := protocol.Bytes32{}
	for i := range ccvAndExecutorHash {
		ccvAndExecutorHash[i] = byte(i)
	}

	message, err := protocol.NewMessage(
		protocol.ChainSelector(1337),
		protocol.ChainSelector(2337),
		protocol.SequenceNumber(12345),
		onRamp,
		offRamp,
		25,
		300_000,
		300_000,
		ccvAndExecutorHash,
		sender,
		receiver,
		destBlob,
		messageData,
		tokenTransfer,
	)
	require.NoError(t, err)
	return message
}

func createMessageWithoutTokenTransfer(t *testing.T) *protocol.Message {
	t.Helper()

	sender, err := protocol.RandomAddress()
	require.NoError(t, err)
	receiver, err := protocol.RandomAddress()
	require.NoError(t, err)
	onRamp, err := protocol.RandomAddress()
	require.NoError(t, err)
	offRamp, err := protocol.RandomAddress()
	require.NoError(t, err)

	destBlob := make([]byte, 30)
	for i := range destBlob {
		destBlob[i] = byte(i + 100)
	}

	messageData := make([]byte, 50)
	for i := range messageData {
		messageData[i] = byte(i + 200)
	}

	ccvAndExecutorHash := protocol.Bytes32{}
	for i := range ccvAndExecutorHash {
		ccvAndExecutorHash[i] = byte(i * 2)
	}

	message, err := protocol.NewMessage(
		protocol.ChainSelector(9999),
		protocol.ChainSelector(8888),
		protocol.SequenceNumber(54321),
		onRamp,
		offRamp,
		10,
		200_000,
		250_000,
		ccvAndExecutorHash,
		sender,
		receiver,
		destBlob,
		messageData,
		nil, // No token transfer
	)
	require.NoError(t, err)
	return message
}

func createMinimalMessage(t *testing.T) *protocol.Message {
	t.Helper()

	sender, err := protocol.RandomAddress()
	require.NoError(t, err)
	receiver, err := protocol.RandomAddress()
	require.NoError(t, err)
	onRamp, err := protocol.RandomAddress()
	require.NoError(t, err)
	offRamp, err := protocol.RandomAddress()
	require.NoError(t, err)

	message, err := protocol.NewMessage(
		protocol.ChainSelector(1),
		protocol.ChainSelector(2),
		protocol.SequenceNumber(1),
		onRamp,
		offRamp,
		1,
		100_000,
		100_000,
		protocol.Bytes32{},
		sender,
		receiver,
		nil, // Empty destBlob
		nil, // Empty data
		nil, // No token transfer
	)
	require.NoError(t, err)
	return message
}

func assertProtocolMessagesEqual(t *testing.T, expected, actual *protocol.Message) {
	t.Helper()

	assert.Equal(t, expected.Version, actual.Version)
	assert.Equal(t, expected.SourceChainSelector, actual.SourceChainSelector)
	assert.Equal(t, expected.DestChainSelector, actual.DestChainSelector)
	assert.Equal(t, expected.SequenceNumber, actual.SequenceNumber)
	assert.Equal(t, expected.OnRampAddressLength, actual.OnRampAddressLength)
	assert.Equal(t, expected.OnRampAddress, actual.OnRampAddress)
	assert.Equal(t, expected.OffRampAddressLength, actual.OffRampAddressLength)
	assert.Equal(t, expected.OffRampAddress, actual.OffRampAddress)
	assert.Equal(t, expected.ExecutionGasLimit, actual.ExecutionGasLimit)
	assert.Equal(t, expected.CcipReceiveGasLimit, actual.CcipReceiveGasLimit)
	assert.Equal(t, expected.Finality, actual.Finality)
	assert.Equal(t, expected.CcvAndExecutorHash, actual.CcvAndExecutorHash)
	assert.Equal(t, expected.SenderLength, actual.SenderLength)
	assert.Equal(t, expected.Sender, actual.Sender)
	assert.Equal(t, expected.ReceiverLength, actual.ReceiverLength)
	assert.Equal(t, expected.Receiver, actual.Receiver)
	assert.Equal(t, expected.DestBlobLength, actual.DestBlobLength)
	assert.Equal(t, expected.DestBlob, actual.DestBlob)
	assert.Equal(t, expected.DataLength, actual.DataLength)
	assert.Equal(t, expected.Data, actual.Data)
	assert.Equal(t, expected.TokenTransferLength, actual.TokenTransferLength)

	if expected.TokenTransfer == nil {
		assert.Nil(t, actual.TokenTransfer)
	} else {
		require.NotNil(t, actual.TokenTransfer)
		assert.Equal(t, expected.TokenTransfer.Version, actual.TokenTransfer.Version)
		assert.Equal(t, expected.TokenTransfer.Amount.String(), actual.TokenTransfer.Amount.String())
		assert.Equal(t, expected.TokenTransfer.SourcePoolAddressLength, actual.TokenTransfer.SourcePoolAddressLength)
		assert.Equal(t, expected.TokenTransfer.SourcePoolAddress, actual.TokenTransfer.SourcePoolAddress)
		assert.Equal(t, expected.TokenTransfer.SourceTokenAddressLength, actual.TokenTransfer.SourceTokenAddressLength)
		assert.Equal(t, expected.TokenTransfer.SourceTokenAddress, actual.TokenTransfer.SourceTokenAddress)
		assert.Equal(t, expected.TokenTransfer.DestTokenAddressLength, actual.TokenTransfer.DestTokenAddressLength)
		assert.Equal(t, expected.TokenTransfer.DestTokenAddress, actual.TokenTransfer.DestTokenAddress)
		assert.Equal(t, expected.TokenTransfer.TokenReceiverLength, actual.TokenTransfer.TokenReceiverLength)
		assert.Equal(t, expected.TokenTransfer.TokenReceiver, actual.TokenTransfer.TokenReceiver)
		assert.Equal(t, expected.TokenTransfer.ExtraDataLength, actual.TokenTransfer.ExtraDataLength)
		assert.Equal(t, expected.TokenTransfer.ExtraData, actual.TokenTransfer.ExtraData)
	}
}

func TestVerifierResult_RoundTrip(t *testing.T) {
	tests := []struct {
		name           string
		verifierResult protocol.VerifierResult
	}{
		{
			name:           "comprehensive verifier result with all fields",
			verifierResult: createComprehensiveVerifierResult(t),
		},
		{
			name:           "verifier result with multiple CCV addresses",
			verifierResult: createVerifierResultWithMultipleCCVAddresses(t),
		},
		{
			name:           "verifier result with minimal fields",
			verifierResult: createMinimalVerifierResult(t),
		},
		{
			name:           "verifier result with empty CCV data",
			verifierResult: createVerifierResultWithEmptyCCVData(t),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Get original message ID
			originalID := tt.verifierResult.MessageID

			// Step 2: Convert protocol.VerifierResult to VerifierResult
			verifierResult := NewVerifierResult(tt.verifierResult)
			require.NotNil(t, verifierResult.VerifierResult)

			// Step 3: Convert back to protocol.VerifierResult
			convertedResult, err := verifierResult.ToVerifierResult()
			require.NoError(t, err)

			convertedID := convertedResult.MessageID
			assert.Equal(t, originalID, convertedID, "MessageID should remain identical after round-trip conversion")
			assertVerifierResultsEqual(t, &tt.verifierResult, &convertedResult)
		})
	}
}

func createComprehensiveVerifierResult(t *testing.T) protocol.VerifierResult {
	t.Helper()

	message := createMinimalMessage(t)
	messageID, err := message.MessageID()
	require.NoError(t, err)

	ccvAddr1, err := protocol.RandomAddress()
	require.NoError(t, err)
	ccvAddr2, err := protocol.RandomAddress()
	require.NoError(t, err)
	ccvAddr3, err := protocol.RandomAddress()
	require.NoError(t, err)

	executorAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	verifierSourceAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	verifierDestAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	ccvData := make([]byte, 100)
	for i := range ccvData {
		ccvData[i] = byte(i)
	}

	return protocol.VerifierResult{
		MessageID:              messageID,
		Message:                *message,
		MessageCCVAddresses:    []protocol.UnknownAddress{ccvAddr1, ccvAddr2, ccvAddr3},
		MessageExecutorAddress: executorAddr,
		CCVData:                ccvData,
		Timestamp:              time.Date(2024, 6, 15, 12, 30, 45, 0, time.UTC),
		VerifierSourceAddress:  verifierSourceAddr,
		VerifierDestAddress:    verifierDestAddr,
	}
}

func createVerifierResultWithMultipleCCVAddresses(t *testing.T) protocol.VerifierResult {
	t.Helper()

	message := createMinimalMessage(t)
	messageID, err := message.MessageID()
	require.NoError(t, err)

	ccvAddresses := make([]protocol.UnknownAddress, 5)
	for i := range ccvAddresses {
		addr, err := protocol.RandomAddress()
		require.NoError(t, err)
		ccvAddresses[i] = addr
	}

	executorAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	verifierSourceAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	verifierDestAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	ccvData := make([]byte, 256)
	for i := range ccvData {
		ccvData[i] = byte(i % 256)
	}

	return protocol.VerifierResult{
		MessageID:              messageID,
		Message:                *message,
		MessageCCVAddresses:    ccvAddresses,
		MessageExecutorAddress: executorAddr,
		CCVData:                ccvData,
		Timestamp:              time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
		VerifierSourceAddress:  verifierSourceAddr,
		VerifierDestAddress:    verifierDestAddr,
	}
}

func createMinimalVerifierResult(t *testing.T) protocol.VerifierResult {
	t.Helper()

	message := createMinimalMessage(t)
	messageID, err := message.MessageID()
	require.NoError(t, err)

	ccvAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	executorAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	verifierSourceAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	verifierDestAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	return protocol.VerifierResult{
		MessageID:              messageID,
		Message:                *message,
		MessageCCVAddresses:    []protocol.UnknownAddress{ccvAddr},
		MessageExecutorAddress: executorAddr,
		CCVData:                []byte{0x01, 0x02, 0x03},
		Timestamp:              time.Unix(1000000000, 0),
		VerifierSourceAddress:  verifierSourceAddr,
		VerifierDestAddress:    verifierDestAddr,
	}
}

func createVerifierResultWithEmptyCCVData(t *testing.T) protocol.VerifierResult {
	t.Helper()

	message := createMinimalMessage(t)
	messageID, err := message.MessageID()
	require.NoError(t, err)

	ccvAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	executorAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	verifierSourceAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	verifierDestAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	return protocol.VerifierResult{
		MessageID:              messageID,
		Message:                *message,
		MessageCCVAddresses:    []protocol.UnknownAddress{ccvAddr},
		MessageExecutorAddress: executorAddr,
		CCVData:                []byte{},
		Timestamp:              time.Unix(1234567890, 0),
		VerifierSourceAddress:  verifierSourceAddr,
		VerifierDestAddress:    verifierDestAddr,
	}
}

func assertVerifierResultsEqual(t *testing.T, expected, actual *protocol.VerifierResult) {
	t.Helper()

	assert.Equal(t, expected.MessageID, actual.MessageID, "MessageID should be equal")
	assertProtocolMessagesEqual(t, &expected.Message, &actual.Message)

	require.Equal(t, len(expected.MessageCCVAddresses), len(actual.MessageCCVAddresses), "CCV addresses count should match")
	for i := range expected.MessageCCVAddresses {
		assert.Equal(t, expected.MessageCCVAddresses[i], actual.MessageCCVAddresses[i], "CCV address at index %d should match", i)
	}

	assert.Equal(t, expected.MessageExecutorAddress, actual.MessageExecutorAddress, "Executor address should match")
	assert.Equal(t, expected.CCVData, actual.CCVData, "CCV data should match")
	assert.Equal(t, expected.Timestamp.Unix(), actual.Timestamp.Unix(), "Timestamp should match")
	assert.Equal(t, expected.VerifierSourceAddress, actual.VerifierSourceAddress, "Verifier source address should match")
	assert.Equal(t, expected.VerifierDestAddress, actual.VerifierDestAddress, "Verifier dest address should match")
}
