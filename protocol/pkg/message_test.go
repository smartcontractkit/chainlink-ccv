package pkg

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

func TestMessageEncodeDecode(t *testing.T) {
	// Create test addresses
	sender, err := RandomAddress()
	require.NoError(t, err)
	receiver, err := RandomAddress()
	require.NoError(t, err)
	onRampAddr, err := RandomAddress()
	require.NoError(t, err)
	offRampAddr, err := RandomAddress()
	require.NoError(t, err)

	// Create empty token transfer
	tokenTransfer := types.NewEmptyTokenTransfer()

	// Create a test message
	msg, err := types.NewMessage(
		types.ChainSelector(1337),
		types.ChainSelector(2337),
		types.Nonce(123),
		onRampAddr,
		offRampAddr,
		10, // finality
		sender,
		receiver,
		[]byte("test dest blob"),
		[]byte("test data"),
		tokenTransfer,
	)
	require.NoError(t, err)

	// Encode
	encoded, err := msg.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	// Decode
	decoded, err := types.DecodeMessage(encoded)
	require.NoError(t, err)

	// Verify all fields match
	assert.Equal(t, msg.Version, decoded.Version)
	assert.Equal(t, msg.SourceChainSelector, decoded.SourceChainSelector)
	assert.Equal(t, msg.DestChainSelector, decoded.DestChainSelector)
	assert.Equal(t, msg.Nonce, decoded.Nonce)
	assert.Equal(t, msg.OnRampAddressLength, decoded.OnRampAddressLength)
	assert.Equal(t, msg.OnRampAddress, decoded.OnRampAddress)
	assert.Equal(t, msg.OffRampAddressLength, decoded.OffRampAddressLength)
	assert.Equal(t, msg.OffRampAddress, decoded.OffRampAddress)
	assert.Equal(t, msg.Finality, decoded.Finality)
	assert.Equal(t, msg.SenderLength, decoded.SenderLength)
	assert.Equal(t, msg.Sender, decoded.Sender)
	assert.Equal(t, msg.ReceiverLength, decoded.ReceiverLength)
	assert.Equal(t, msg.Receiver, decoded.Receiver)
	assert.Equal(t, msg.DestBlobLength, decoded.DestBlobLength)
	assert.Equal(t, msg.DestBlob, decoded.DestBlob)
	assert.Equal(t, msg.TokenTransferLength, decoded.TokenTransferLength)
	assert.Equal(t, msg.TokenTransfer, decoded.TokenTransfer)
	assert.Equal(t, msg.DataLength, decoded.DataLength)
	assert.Equal(t, msg.Data, decoded.Data)
}

func TestMessageID(t *testing.T) {
	// Create two identical messages
	sender, err := RandomAddress()
	require.NoError(t, err)
	receiver, err := RandomAddress()
	require.NoError(t, err)
	onRampAddr, err := RandomAddress()
	require.NoError(t, err)
	offRampAddr, err := RandomAddress()
	require.NoError(t, err)
	tokenTransfer := types.NewEmptyTokenTransfer()

	msg1, err := types.NewMessage(
		types.ChainSelector(1337),
		types.ChainSelector(2337),
		types.Nonce(123),
		onRampAddr,
		offRampAddr,
		10,
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		tokenTransfer,
	)
	require.NoError(t, err)

	msg2, err := types.NewMessage(
		types.ChainSelector(1337),
		types.ChainSelector(2337),
		types.Nonce(123),
		onRampAddr,
		offRampAddr,
		10,
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		tokenTransfer,
	)
	require.NoError(t, err)

	// Same messages should have same message ID
	id1, err := msg1.MessageID()
	require.NoError(t, err)
	id2, err := msg2.MessageID()
	require.NoError(t, err)
	assert.Equal(t, id1, id2)

	// Different nonce should give different message ID
	msg3, err := types.NewMessage(
		types.ChainSelector(1337),
		types.ChainSelector(2337),
		types.Nonce(124), // Different nonce
		onRampAddr,
		offRampAddr,
		10,
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		tokenTransfer,
	)
	require.NoError(t, err)

	id3, err := msg3.MessageID()
	require.NoError(t, err)
	assert.NotEqual(t, id1, id3)
}

// TestMessageDecodingErrors tests message decoding error conditions.
func TestMessageDecodingErrors(t *testing.T) {
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
				// Set chain selectors and nonce (8 bytes each)
				binary.BigEndian.PutUint64(data[1:9], 1)   // source chain
				binary.BigEndian.PutUint64(data[9:17], 2)  // dest chain
				binary.BigEndian.PutUint64(data[17:25], 3) // nonce
				data[25] = 10                              // claim 10 bytes for on-ramp address
				data[26] = 0                               // but only provide 0 bytes for off-ramp
				return data
			}(),
			expectErr: "failed to read on-ramp address",
		},
		{
			name:      "test",
			data:      []byte("AS7mNJUe9xtGs1ZzPiKSRPIAAAAAAAAAARSaZ254GlI7XQwOQ3MTE6cIy2B1CCAAAAAAAAAAAAAAAAANzRv5obNs40I37q/vIgkyhGvNggABFPOf1uUarYj29M5quIJyec//uSJmFDql67ENx5fKyChSTlmjM9CjcUQ8AAAAAAAA"),
			expectErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := types.DecodeMessage(tt.data)
			fmt.Printf("%+v\n", msg)
			fmt.Printf("error: %+v\n", err)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectErr)
		})
	}
}
