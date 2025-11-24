package protocol

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenTransferEncodeDecode(t *testing.T) {
	// Create a test token transfer
	tt := &TokenTransfer{
		Version:                  1,
		Amount:                   big.NewInt(1000),
		SourceTokenAddressLength: 3,
		SourceTokenAddress:       []byte("abc"),
		DestTokenAddressLength:   4,
		DestTokenAddress:         []byte("wxyz"),
		TokenReceiverLength:      2,
		TokenReceiver:            []byte("R1"),
		ExtraDataLength:          5,
		ExtraData:                []byte("hello"),
	}

	// Encode
	encoded := tt.Encode()
	require.NotEmpty(t, encoded)

	// Decode
	decoded, err := DecodeTokenTransfer(encoded)
	require.NoError(t, err)

	// Verify all fields match
	assert.Equal(t, tt.Version, decoded.Version)
	assert.Equal(t, tt.Amount.Cmp(decoded.Amount), 0)
	assert.Equal(t, tt.SourceTokenAddressLength, decoded.SourceTokenAddressLength)
	assert.Equal(t, tt.SourceTokenAddress, decoded.SourceTokenAddress)
	assert.Equal(t, tt.DestTokenAddressLength, decoded.DestTokenAddressLength)
	assert.Equal(t, tt.DestTokenAddress, decoded.DestTokenAddress)
	assert.Equal(t, tt.TokenReceiverLength, decoded.TokenReceiverLength)
	assert.Equal(t, tt.TokenReceiver, decoded.TokenReceiver)
	assert.Equal(t, tt.ExtraDataLength, decoded.ExtraDataLength)
	assert.Equal(t, tt.ExtraData, decoded.ExtraData)
}

func TestEmptyTokenTransfer(t *testing.T) {
	tt := NewEmptyTokenTransfer()

	assert.Equal(t, uint8(MessageVersion), tt.Version)
	assert.Equal(t, big.NewInt(0).Cmp(tt.Amount), 0)
	assert.Equal(t, uint8(0), tt.SourceTokenAddressLength)
	assert.Empty(t, tt.SourceTokenAddress)
	assert.Equal(t, uint8(0), tt.DestTokenAddressLength)
	assert.Empty(t, tt.DestTokenAddress)
	assert.Equal(t, uint8(0), tt.TokenReceiverLength)
	assert.Empty(t, tt.TokenReceiver)
	assert.Equal(t, uint16(0), tt.ExtraDataLength)
	assert.Empty(t, tt.ExtraData)

	// Should be able to encode/decode
	encoded := tt.Encode()
	decoded, err := DecodeTokenTransfer(encoded)
	require.NoError(t, err)
	assert.Equal(t, tt.Version, decoded.Version)
	assert.Equal(t, tt.Amount.Cmp(decoded.Amount), 0)
}

// TestTokenTransferEdgeCases tests edge cases for token transfer encoding/decoding.
func TestTokenTransferEdgeCases(t *testing.T) {
	tests := []struct {
		transfer  *TokenTransfer
		name      string
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

// TestTokenTransferDecodingErrors tests decoding error conditions.
func TestTokenTransferDecodingErrors(t *testing.T) {
	tests := []struct {
		name      string
		expectErr string
		data      []byte
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
				data[33] = 10 // claim 10 bytes for source pool address
				// but don't provide 10 bytes
				return data
			}(),
			expectErr: "failed to read source pool address",
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
