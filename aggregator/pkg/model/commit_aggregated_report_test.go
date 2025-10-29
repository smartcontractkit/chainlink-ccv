package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReceiptBlob_JSONSerialization(t *testing.T) {
	// Create a test receipt blob
	blob := &ReceiptBlob{
		Issuer:            []byte{0x12, 0x34, 0x56, 0x78},
		DestGasLimit:      200000,
		DestBytesOverhead: 2000,
		Blob:              []byte("test-blob-data"),
		ExtraArgs:         []byte("test-args"),
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(blob)
	require.NoError(t, err)

	// Verify the JSON is human-readable
	expectedJSON := `{"issuer":"12345678","dest_gas_limit":200000,"dest_bytes_overhead":2000,"blob":"746573742d626c6f622d64617461","extra_args":"746573742d61726773"}`
	require.JSONEq(t, expectedJSON, string(jsonData))

	// Deserialize back to ReceiptBlob
	var deserializedBlob ReceiptBlob
	err = json.Unmarshal(jsonData, &deserializedBlob)
	require.NoError(t, err)

	// Verify the deserialized blob matches the original
	require.Equal(t, blob.Issuer, deserializedBlob.Issuer)
	require.Equal(t, blob.DestGasLimit, deserializedBlob.DestGasLimit)
	require.Equal(t, blob.DestBytesOverhead, deserializedBlob.DestBytesOverhead)
	require.Equal(t, blob.Blob, deserializedBlob.Blob)
	require.Equal(t, blob.ExtraArgs, deserializedBlob.ExtraArgs)
}

func TestSerializeReceiptBlobsJSON(t *testing.T) {
	blobs := []*ReceiptBlob{
		{
			Issuer:            []byte{0x12, 0x34},
			DestGasLimit:      100000,
			DestBytesOverhead: 1000,
			Blob:              []byte("blob1"),
			ExtraArgs:         []byte("args1"),
		},
		{
			Issuer:            []byte{0x56, 0x78},
			DestGasLimit:      200000,
			DestBytesOverhead: 2000,
			Blob:              []byte("blob2"),
			ExtraArgs:         []byte("args2"),
		},
	}

	// Serialize using our helper function
	jsonData, err := SerializeReceiptBlobsJSON(blobs)
	require.NoError(t, err)

	// Verify it's valid JSON and human-readable
	var jsonStructure []any
	err = json.Unmarshal(jsonData, &jsonStructure)
	require.NoError(t, err)
	require.Len(t, jsonStructure, 2)

	// Deserialize back using our helper function
	deserializedBlobs, err := DeserializeReceiptBlobsJSON(jsonData)
	require.NoError(t, err)
	require.Len(t, deserializedBlobs, 2)

	// Verify the first blob
	require.Equal(t, blobs[0].Issuer, deserializedBlobs[0].Issuer)
	require.Equal(t, blobs[0].DestGasLimit, deserializedBlobs[0].DestGasLimit)
	require.Equal(t, blobs[0].DestBytesOverhead, deserializedBlobs[0].DestBytesOverhead)
	require.Equal(t, blobs[0].Blob, deserializedBlobs[0].Blob)
	require.Equal(t, blobs[0].ExtraArgs, deserializedBlobs[0].ExtraArgs)

	// Verify the second blob
	require.Equal(t, blobs[1].Issuer, deserializedBlobs[1].Issuer)
	require.Equal(t, blobs[1].DestGasLimit, deserializedBlobs[1].DestGasLimit)
	require.Equal(t, blobs[1].DestBytesOverhead, deserializedBlobs[1].DestBytesOverhead)
	require.Equal(t, blobs[1].Blob, deserializedBlobs[1].Blob)
	require.Equal(t, blobs[1].ExtraArgs, deserializedBlobs[1].ExtraArgs)
}

func TestReceiptBlob_JSONSerialization_Demo(t *testing.T) {
	// Create example receipt blobs like the ones in our test
	blobs := []*ReceiptBlob{
		{
			Issuer:            []byte{0x69, 0x47, 0xb5, 0x74, 0xb7, 0x4b, 0xb2, 0xdb, 0xac, 0x3a, 0x8d, 0xc7, 0x14, 0x2a, 0x35, 0x1f, 0x6a, 0xa7, 0x63, 0x97},
			DestGasLimit:      100000,
			DestBytesOverhead: 1000,
			Blob:              []byte("minority-blob-data"),
			ExtraArgs:         []byte("minority-args"),
		},
		{
			Issuer:            []byte{0x69, 0x47, 0xb5, 0x74, 0xb7, 0x4b, 0xb2, 0xdb, 0xac, 0x3a, 0x8d, 0xc7, 0x14, 0x2a, 0x35, 0x1f, 0x6a, 0xa7, 0x63, 0x97},
			DestGasLimit:      200000,
			DestBytesOverhead: 2000,
			Blob:              []byte("majority-blob-data"),
			ExtraArgs:         []byte("majority-args"),
		},
	}

	// Serialize to JSON using our helper function
	jsonData, err := SerializeReceiptBlobsJSON(blobs)
	require.NoError(t, err)

	// Pretty print the JSON to show what it looks like in the database
	var prettyJSON any
	err = json.Unmarshal(jsonData, &prettyJSON)
	require.NoError(t, err)

	prettyBytes, err := json.MarshalIndent(prettyJSON, "", "  ")
	require.NoError(t, err)

	t.Logf("Receipt Blobs as JSON (human-readable for database debugging):\n%s", string(prettyBytes))

	// Verify the JSON contains all expected fields in readable format
	jsonStr := string(jsonData)
	require.Contains(t, jsonStr, "6947b574b74bb2dbac3a8dc7142a351f6aa76397") // issuer as hex
	require.Contains(t, jsonStr, "100000")                                   // dest_gas_limit
	require.Contains(t, jsonStr, "200000")                                   // dest_gas_limit
	require.Contains(t, jsonStr, "6d696e6f726974792d626c6f622d64617461")     // "minority-blob-data" as hex
	require.Contains(t, jsonStr, "6d616a6f726974792d626c6f622d64617461")     // "majority-blob-data" as hex
}

func TestReceiptBlob_JSONSerialization_NilValues(t *testing.T) {
	// Test with nil blob
	var nilBlob *ReceiptBlob
	jsonData, err := json.Marshal(nilBlob)
	require.NoError(t, err)
	require.Equal(t, "null", string(jsonData))

	// Test with nil slice
	nilSlice, err := SerializeReceiptBlobsJSON(nil)
	require.NoError(t, err)
	require.Nil(t, nilSlice)

	// Test deserializing nil slice
	deserializedNil, err := DeserializeReceiptBlobsJSON(nil)
	require.NoError(t, err)
	require.Nil(t, deserializedNil)

	// Test deserializing empty slice
	deserializedEmpty, err := DeserializeReceiptBlobsJSON([]byte{})
	require.NoError(t, err)
	require.Nil(t, deserializedEmpty)
}

func TestReceiptBlob_Less(t *testing.T) {
	tests := []struct {
		name     string
		a        *ReceiptBlob
		b        *ReceiptBlob
		expected bool
	}{
		{
			name:     "nil handling - both nil",
			a:        nil,
			b:        nil,
			expected: false,
		},
		{
			name:     "nil handling - a is nil",
			a:        nil,
			b:        &ReceiptBlob{Issuer: []byte{1}},
			expected: true,
		},
		{
			name:     "nil handling - b is nil",
			a:        &ReceiptBlob{Issuer: []byte{1}},
			b:        nil,
			expected: false,
		},
		{
			name:     "different issuers",
			a:        &ReceiptBlob{Issuer: []byte{1, 2, 3}},
			b:        &ReceiptBlob{Issuer: []byte{2, 3, 4}},
			expected: true,
		},
		{
			name:     "same issuer, different gas limit",
			a:        &ReceiptBlob{Issuer: []byte{1, 2, 3}, DestGasLimit: 100},
			b:        &ReceiptBlob{Issuer: []byte{1, 2, 3}, DestGasLimit: 200},
			expected: true,
		},
		{
			name:     "same issuer and gas limit, different bytes overhead",
			a:        &ReceiptBlob{Issuer: []byte{1, 2, 3}, DestGasLimit: 100, DestBytesOverhead: 10},
			b:        &ReceiptBlob{Issuer: []byte{1, 2, 3}, DestGasLimit: 100, DestBytesOverhead: 20},
			expected: true,
		},
		{
			name:     "same issuer, gas limit, and bytes overhead, different blob",
			a:        &ReceiptBlob{Issuer: []byte{1, 2, 3}, DestGasLimit: 100, DestBytesOverhead: 10, Blob: []byte{1}},
			b:        &ReceiptBlob{Issuer: []byte{1, 2, 3}, DestGasLimit: 100, DestBytesOverhead: 10, Blob: []byte{2}},
			expected: true,
		},
		{
			name:     "all same except extra args",
			a:        &ReceiptBlob{Issuer: []byte{1, 2, 3}, DestGasLimit: 100, DestBytesOverhead: 10, Blob: []byte{1}, ExtraArgs: []byte{1}},
			b:        &ReceiptBlob{Issuer: []byte{1, 2, 3}, DestGasLimit: 100, DestBytesOverhead: 10, Blob: []byte{1}, ExtraArgs: []byte{2}},
			expected: true,
		},
		{
			name:     "completely identical",
			a:        &ReceiptBlob{Issuer: []byte{1, 2, 3}, DestGasLimit: 100, DestBytesOverhead: 10, Blob: []byte{1}, ExtraArgs: []byte{1}},
			b:        &ReceiptBlob{Issuer: []byte{1, 2, 3}, DestGasLimit: 100, DestBytesOverhead: 10, Blob: []byte{1}, ExtraArgs: []byte{1}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.a.Less(tt.b)
			if result != tt.expected {
				t.Errorf("Less() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
