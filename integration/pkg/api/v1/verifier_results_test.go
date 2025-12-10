package v1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

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
