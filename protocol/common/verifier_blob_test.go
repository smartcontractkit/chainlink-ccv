package common

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifierBlobEncoding tests the new length-prefixed verifier blob structure
func TestVerifierBlobEncoding(t *testing.T) {
	nonce := uint64(12345)

	// Encode
	encoded, err := EncodeVerifierBlob(nonce)
	require.NoError(t, err)
	assert.Len(t, encoded, 11) // Should be 2 (length) + 1 (version) + 8 (nonce) = 11 bytes

	// Decode using the simple function (just extracts nonce)
	decodedNonce, err := DecodeReceiptBlob(encoded)
	require.NoError(t, err)
	assert.Equal(t, nonce, decodedNonce)

	// Decode using the full function
	decodedBlob, err := DecodeVerifierBlobData(encoded)
	require.NoError(t, err)
	assert.Equal(t, uint8(1), decodedBlob.Version)
	assert.Equal(t, nonce, decodedBlob.Nonce)
}

// TestVerifierBlobVersionValidation tests version validation
func TestVerifierBlobVersionValidation(t *testing.T) {
	// Create blob with invalid version using length-prefixed format
	var content bytes.Buffer
	content.WriteByte(99) // Invalid version
	err := binary.Write(&content, binary.BigEndian, uint64(123))
	require.NoError(t, err)

	var buf bytes.Buffer
	contentBytes := content.Bytes()
	err = binary.Write(&buf, binary.BigEndian, uint16(len(contentBytes)))
	require.NoError(t, err)
	buf.Write(contentBytes)

	invalidBlob := buf.Bytes()

	_, err = DecodeReceiptBlob(invalidBlob)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported verifier blob version")
}

// TestVerifierBlobRoundTrip tests round-trip encoding with various nonce values
func TestVerifierBlobRoundTrip(t *testing.T) {
	testCases := []uint64{
		0,          // minimum
		1,          // small value
		12345,      // medium value
		^uint64(0), // maximum uint64
	}

	for _, nonce := range testCases {
		t.Run(fmt.Sprintf("nonce_%d", nonce), func(t *testing.T) {
			// Encode
			encoded, err := EncodeVerifierBlob(nonce)
			require.NoError(t, err)
			assert.Len(t, encoded, 11) // 2 (length) + 1 (version) + 8 (nonce)

			// Decode
			decoded, err := DecodeReceiptBlob(encoded)
			require.NoError(t, err)
			assert.Equal(t, nonce, decoded)
		})
	}
}

// TestLengthPrefixedBlobEdgeCases tests edge cases for the length-prefixed verifier blob format
func TestLengthPrefixedBlobEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		expectErr string
	}{
		{
			name:      "empty_blob",
			data:      []byte{},
			expectErr: "receipt blob too short",
		},
		{
			name:      "only_one_byte",
			data:      []byte{0x01},
			expectErr: "receipt blob too short",
		},
		{
			name: "length_mismatch_too_short",
			data: func() []byte {
				var buf bytes.Buffer
				err := binary.Write(&buf, binary.BigEndian, uint16(10))
				if err != nil {
					t.Fatalf("Failed to write to buffer: %v", err)
				}
				buf.Write([]byte{1, 2, 3}) // But only provide 3 bytes
				return buf.Bytes()
			}(),
			expectErr: "insufficient data",
		},
		{
			name: "zero_length_content",
			data: func() []byte {
				var buf bytes.Buffer
				err := binary.Write(&buf, binary.BigEndian, uint16(0))
				if err != nil {
					t.Fatalf("Failed to write to buffer: %v", err)
				}
				return buf.Bytes()
			}(),
			expectErr: "failed to read version", // Should fail when trying to read version from empty content
		},
		{
			name: "valid_minimal_blob",
			data: func() []byte {
				// Create minimal valid blob: just version byte
				var content bytes.Buffer
				content.WriteByte(1) // version only

				var buf bytes.Buffer
				contentBytes := content.Bytes()
				err := binary.Write(&buf, binary.BigEndian, uint16(len(contentBytes)))
				if err != nil {
					t.Fatalf("Failed to write to buffer: %v", err)
				}
				buf.Write(contentBytes)
				return buf.Bytes()
			}(),
			expectErr: "failed to read nonce", // Should fail when trying to read nonce
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeReceiptBlob(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectErr)
		})
	}
}

// TestLengthPrefixedBlobFlexibility tests that the format can handle different content sizes
func TestLengthPrefixedBlobFlexibility(t *testing.T) {
	// Test that we can create blobs with additional data beyond just nonce
	tests := []struct {
		name        string
		version     uint8
		nonce       uint64
		extraData   []byte
		expectValid bool
	}{
		{
			name:        "standard_blob",
			version:     1,
			nonce:       12345,
			extraData:   nil,
			expectValid: true,
		},
		{
			name:        "blob_with_extra_data",
			version:     1,
			nonce:       67890,
			extraData:   []byte("future_extension_data"),
			expectValid: true, // Should decode successfully, extra data ignored for now
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Manually create blob with extra data
			var content bytes.Buffer
			content.WriteByte(tt.version)
			err := binary.Write(&content, binary.BigEndian, tt.nonce)
			require.NoError(t, err)
			if tt.extraData != nil {
				content.Write(tt.extraData)
			}

			// Create length-prefixed blob
			var buf bytes.Buffer
			contentBytes := content.Bytes()
			err = binary.Write(&buf, binary.BigEndian, uint16(len(contentBytes)))
			require.NoError(t, err)
			buf.Write(contentBytes)

			encoded := buf.Bytes()

			// Decode
			decodedNonce, err := DecodeReceiptBlob(encoded)
			if tt.expectValid {
				require.NoError(t, err)
				assert.Equal(t, tt.nonce, decodedNonce)

				// Also test full blob decoding
				decodedBlob, err := DecodeVerifierBlobData(encoded)
				require.NoError(t, err)
				assert.Equal(t, tt.version, decodedBlob.Version)
				assert.Equal(t, tt.nonce, decodedBlob.Nonce)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// TestMaximumBlobSize tests handling of large blobs
func TestMaximumBlobSize(t *testing.T) {
	// Test maximum uint16 length (65535 bytes)
	maxContentSize := int(^uint16(0)) // 65535

	var content bytes.Buffer
	content.WriteByte(1) // version
	err := binary.Write(&content, binary.BigEndian, uint64(12345))
	require.NoError(t, err)

	// Add padding to reach maximum size
	remainingSize := maxContentSize - content.Len()
	if remainingSize > 0 {
		content.Write(make([]byte, remainingSize))
	}

	// Create length-prefixed blob
	var buf bytes.Buffer
	contentBytes := content.Bytes()
	err = binary.Write(&buf, binary.BigEndian, uint16(len(contentBytes)))
	require.NoError(t, err)
	buf.Write(contentBytes)

	encoded := buf.Bytes()

	// Should be able to decode successfully
	decodedNonce, err := DecodeReceiptBlob(encoded)
	require.NoError(t, err)
	assert.Equal(t, uint64(12345), decodedNonce)

	// Verify total size
	assert.Equal(t, maxContentSize+2, len(encoded)) // +2 for length prefix
}

// TestVerifierBlobStructure tests the internal structure of verifier blobs
func TestVerifierBlobStructure(t *testing.T) {
	nonce := uint64(0xDEADBEEFCAFEBABE)

	// Encode
	encoded, err := EncodeVerifierBlob(nonce)
	require.NoError(t, err)

	// Manually verify the structure
	reader := bytes.NewReader(encoded)

	// Check length prefix
	var length uint16
	err = binary.Read(reader, binary.BigEndian, &length)
	require.NoError(t, err)
	assert.Equal(t, uint16(9), length) // version(1) + nonce(8)

	// Check version
	version, err := reader.ReadByte()
	require.NoError(t, err)
	assert.Equal(t, uint8(1), version)

	// Check nonce
	var decodedNonce uint64
	err = binary.Read(reader, binary.BigEndian, &decodedNonce)
	require.NoError(t, err)
	assert.Equal(t, nonce, decodedNonce)

	// Should have consumed all data
	assert.Equal(t, 0, reader.Len())
}

// TestVerifierBlobCompactness tests that the format is as compact as possible
func TestVerifierBlobCompactness(t *testing.T) {
	testCases := []struct {
		nonce        uint64
		expectedSize int
	}{
		{0, 11},          // minimum nonce
		{12345, 11},      // typical nonce
		{^uint64(0), 11}, // maximum nonce
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("nonce_%d", tc.nonce), func(t *testing.T) {
			encoded, err := EncodeVerifierBlob(tc.nonce)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedSize, len(encoded), "blob size should be consistent regardless of nonce value")
		})
	}
}
