package common

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTokenTransferEdgeCases tests edge cases for token transfer encoding/decoding
func TestTokenTransferEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		transfer  *TokenTransfer
		expectErr bool
	}{
		{
			name: "maximum_values",
			transfer: &TokenTransfer{
				Version:                  255,
				Amount:                   new(big.Int).Lsh(big.NewInt(1), 256).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), // 2^256 - 1
				SourceTokenAddressLength: 255,
				SourceTokenAddress:       make([]byte, 255),
				DestTokenAddressLength:   255,
				DestTokenAddress:         make([]byte, 255),
				TokenReceiverLength:      255,
				TokenReceiver:            make([]byte, 255),
				ExtraDataLength:          255,
				ExtraData:                make([]byte, 255),
			},
			expectErr: false,
		},
		{
			name: "zero_values",
			transfer: &TokenTransfer{
				Version:                  0,
				Amount:                   big.NewInt(0),
				SourceTokenAddressLength: 0,
				SourceTokenAddress:       []byte{},
				DestTokenAddressLength:   0,
				DestTokenAddress:         []byte{},
				TokenReceiverLength:      0,
				TokenReceiver:            []byte{},
				ExtraDataLength:          0,
				ExtraData:                []byte{},
			},
			expectErr: false,
		},
		{
			name: "nil_amount",
			transfer: &TokenTransfer{
				Version:                  1,
				Amount:                   nil,
				SourceTokenAddressLength: 0,
				SourceTokenAddress:       []byte{},
				DestTokenAddressLength:   0,
				DestTokenAddress:         []byte{},
				TokenReceiverLength:      0,
				TokenReceiver:            []byte{},
				ExtraDataLength:          0,
				ExtraData:                []byte{},
			},
			expectErr: false, // Should handle nil amount gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded := tt.transfer.Encode()
			require.NotEmpty(t, encoded)

			// Decode
			decoded, err := DecodeTokenTransfer(encoded)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Verify
			assert.Equal(t, tt.transfer.Version, decoded.Version)
			if tt.transfer.Amount == nil {
				assert.Equal(t, big.NewInt(0).Cmp(decoded.Amount), 0)
			} else {
				assert.Equal(t, tt.transfer.Amount.Cmp(decoded.Amount), 0)
			}
		})
	}
}

// TestTokenTransferDecodingErrors tests decoding error conditions
func TestTokenTransferDecodingErrors(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		expectErr string
	}{
		{
			name:      "empty_data",
			data:      []byte{},
			expectErr: "data too short",
		},
		{
			name:      "too_short",
			data:      []byte{1, 2, 3},
			expectErr: "data too short",
		},
		{
			name:      "truncated_amount",
			data:      make([]byte, 10), // Less than 34 bytes minimum
			expectErr: "data too short",
		},
		{
			name: "invalid_length_mismatch",
			data: func() []byte {
				// Create valid header but with mismatched length
				data := make([]byte, 34)
				data[0] = 1   // version
				data[33] = 10 // claim 10 bytes for source address
				// but don't provide 10 bytes
				return data
			}(),
			expectErr: "failed to read source token address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeTokenTransfer(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectErr)
		})
	}
}

// TestMessageDecodingErrors tests message decoding error conditions
func TestMessageDecodingErrors(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		expectErr string
	}{
		{
			name:      "empty_data",
			data:      []byte{},
			expectErr: "data too short",
		},
		{
			name:      "too_short",
			data:      make([]byte, 10),
			expectErr: "data too short",
		},
		{
			name:      "truncated_chain_selector",
			data:      []byte{1}, // Just version
			expectErr: "data too short",
		},
		{
			name: "invalid_address_length",
			data: func() []byte {
				// Create minimal valid header
				data := make([]byte, 27) // minimum size
				data[0] = 1              // version
				// Set chain selectors and sequence number (8 bytes each)
				binary.BigEndian.PutUint64(data[1:9], 1)   // source chain
				binary.BigEndian.PutUint64(data[9:17], 2)  // dest chain
				binary.BigEndian.PutUint64(data[17:25], 3) // sequence number
				data[25] = 10                              // claim 10 bytes for on-ramp address
				data[26] = 0                               // but only provide 0 bytes for off-ramp
				return data
			}(),
			expectErr: "failed to read on-ramp address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeMessage(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectErr)
		})
	}
}
