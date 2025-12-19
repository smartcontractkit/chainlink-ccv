package protocol

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// Create a test message w/ token transfer
	msg1, err := NewMessage(
		ChainSelector(1337),
		ChainSelector(2337),
		SequenceNumber(123), // sequence number
		onRampAddr,
		offRampAddr,
		10,        // finality
		200_000,   // execution gas limit
		100_000,   // ccip receive gas limit
		Bytes32{}, // ccvAndExecutorHash
		sender,
		receiver,
		[]byte("test dest blob"),
		[]byte("test data"),
		NewEmptyTokenTransfer(),
	)
	require.NoError(t, err)

	// Create a test message w/o token transfer
	msg2, err := NewMessage(
		ChainSelector(1337),
		ChainSelector(2337),
		123, // sequence number
		onRampAddr,
		offRampAddr,
		10,        // finality
		200_000,   // execution gas limit
		100_000,   // ccip receive gas limit
		Bytes32{}, // ccvAndExecutorHash
		sender,
		receiver,
		[]byte("test dest blob"),
		[]byte("test data"),
		nil,
	)
	require.NoError(t, err)

	for _, msg := range []*Message{msg1, msg2} {
		// Encode
		encoded, err := msg.Encode()
		require.NoError(t, err)
		require.NotEmpty(t, encoded)

		// Decode
		decoded, err := DecodeMessage(encoded)
		require.NoError(t, err)

		// Verify all fields match
		assert.Equal(t, msg.Version, decoded.Version)
		assert.Equal(t, msg.SourceChainSelector, decoded.SourceChainSelector)
		assert.Equal(t, msg.DestChainSelector, decoded.DestChainSelector)
		assert.Equal(t, msg.SequenceNumber, decoded.SequenceNumber)
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
		// Compare TokenTransfer structs
		if msg.TokenTransfer == nil {
			assert.Nil(t, decoded.TokenTransfer)
		} else {
			require.NotNil(t, decoded.TokenTransfer)
			assert.Equal(t, msg.TokenTransfer, decoded.TokenTransfer)
		}
		assert.Equal(t, msg.DataLength, decoded.DataLength)
		assert.Equal(t, msg.Data, decoded.Data)
	}
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
	tokenTransfer := NewEmptyTokenTransfer()

	msg1, err := NewMessage(
		ChainSelector(1337),
		ChainSelector(2337),
		123, // sequence number
		onRampAddr,
		offRampAddr,
		10,        // finality
		200_000,   // execution gas limit
		100_000,   // ccip receive gas limit
		Bytes32{}, // ccvAndExecutorHash
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		tokenTransfer,
	)
	require.NoError(t, err)

	msg2, err := NewMessage(
		ChainSelector(1337),
		ChainSelector(2337),
		123, // sequence number
		onRampAddr,
		offRampAddr,
		10,        // finality
		200_000,   // execution gas limit
		100_000,   // ccip receive gas limit
		Bytes32{}, // ccvAndExecutorHash
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

	// Different sequence number should give different message ID
	msg3, err := NewMessage(
		ChainSelector(1337),
		ChainSelector(2337),
		SequenceNumber(124), // Different sequence number
		onRampAddr,
		offRampAddr,
		10,        // finality
		200_000,   // execution gas limit
		100_000,   // ccip receive gas limit
		Bytes32{}, // ccvAndExecutorHash
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
			expectErr: "failed to read execution gas limit",
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

func TestMessageDiscoveryVersion(t *testing.T) {
	vHash := Keccak256([]byte("CCIP1.7_MessageDiscovery_Version"))
	version := vHash[:4]
	require.Equal(t, MessageDiscoveryVersion, version)
}

func TestMessageCCVHashValidation(t *testing.T) {
	verifierAddress, err := NewUnknownAddressFromHex("0x8fb4c06de17cefca5a89b013ac003e51445bac81")
	require.NoError(t, err)
	executorAddress, err := NewUnknownAddressFromHex("0x54802db75581604cd29835eb03a4854d60e530a8")
	require.NoError(t, err)

	ccvHash := "0x50ca3349fc87e9129c329ec5ad80180f19aabf50d85de8378e0441044854c10a"

	derivedHash, err := ComputeCCVAndExecutorHash([]UnknownAddress{verifierAddress}, executorAddress)
	require.NoError(t, err)
	require.Equal(t, ccvHash, derivedHash.String())
}

// TestMessage_Encode_LengthMismatch tests that Encode returns errors when length fields don't match data.
func TestMessage_Encode_LengthMismatch(t *testing.T) {
	tests := []struct {
		name        string
		msg         *Message
		expectedErr string
	}{
		{
			name: "OnRampAddressLength_mismatch",
			msg: &Message{
				Version:             1,
				OnRampAddressLength: 20,              // claims 20 bytes
				OnRampAddress:       []byte("short"), // only 5 bytes
			},
			expectedErr: "OnRampAddressLength mismatch",
		},
		{
			name: "OffRampAddressLength_mismatch",
			msg: &Message{
				Version:              1,
				OffRampAddressLength: 20,              // claims 20 bytes
				OffRampAddress:       []byte("short"), // only 5 bytes
			},
			expectedErr: "OffRampAddressLength mismatch",
		},
		{
			name: "SenderLength_mismatch",
			msg: &Message{
				Version:      1,
				SenderLength: 20,           // claims 20 bytes
				Sender:       []byte("ab"), // only 2 bytes
			},
			expectedErr: "SenderLength mismatch",
		},
		{
			name: "ReceiverLength_mismatch",
			msg: &Message{
				Version:        1,
				ReceiverLength: 20,           // claims 20 bytes
				Receiver:       []byte("ab"), // only 2 bytes
			},
			expectedErr: "ReceiverLength mismatch",
		},
		{
			name: "DestBlobLength_mismatch",
			msg: &Message{
				Version:        1,
				DestBlobLength: 100,             // claims 100 bytes
				DestBlob:       []byte("small"), // only 5 bytes
			},
			expectedErr: "DestBlobLength mismatch",
		},
		{
			name: "DataLength_mismatch",
			msg: &Message{
				Version:    1,
				DataLength: 50,           // claims 50 bytes
				Data:       []byte("hi"), // only 2 bytes
			},
			expectedErr: "DataLength mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.msg.Encode()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

// TestComputeCCVAndExecutorHash_VariableLengthAddresses tests chain-agnostic address handling.
func TestComputeCCVAndExecutorHash_VariableLengthAddresses(t *testing.T) {
	tests := []struct {
		name          string
		ccvAddresses  []UnknownAddress
		executorAddr  UnknownAddress
		expectedErr   string
		expectSuccess bool
	}{
		{
			name:          "32_byte_addresses_valid",
			ccvAddresses:  []UnknownAddress{make([]byte, 32), make([]byte, 32)},
			executorAddr:  make([]byte, 32),
			expectSuccess: true,
		},
		{
			name:          "single_byte_addresses_valid",
			ccvAddresses:  []UnknownAddress{make([]byte, 1)},
			executorAddr:  make([]byte, 1),
			expectSuccess: true,
		},
		{
			name:          "empty_ccv_addresses_valid",
			ccvAddresses:  []UnknownAddress{},
			executorAddr:  make([]byte, 20),
			expectSuccess: true,
		},
		{
			name:          "mixed_length_addresses_invalid",
			ccvAddresses:  []UnknownAddress{make([]byte, 20), make([]byte, 32)},
			executorAddr:  make([]byte, 20),
			expectedErr:   "CCV address at index 1 has different length",
			expectSuccess: false,
		},
		{
			name:          "ccv_different_from_executor_invalid",
			ccvAddresses:  []UnknownAddress{make([]byte, 32)},
			executorAddr:  make([]byte, 20),
			expectedErr:   "CCV address at index 0 has different length",
			expectSuccess: false,
		},
		{
			name:          "empty_executor_address_invalid",
			ccvAddresses:  []UnknownAddress{},
			executorAddr:  []byte{},
			expectedErr:   "executor address length cannot be 0",
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := ComputeCCVAndExecutorHash(tt.ccvAddresses, tt.executorAddr)
			if tt.expectSuccess {
				require.NoError(t, err)
				assert.NotEqual(t, Bytes32{}, hash)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

// TestComputeCCVAndExecutorHash_TooManyCCVs tests the MaxCCVsPerMessage limit.
func TestComputeCCVAndExecutorHash_TooManyCCVs(t *testing.T) {
	// Create 256 CCV addresses (one more than max)
	ccvAddresses := make([]UnknownAddress, MaxCCVsPerMessage+1)
	for i := range ccvAddresses {
		ccvAddresses[i] = make([]byte, 20)
	}
	executorAddr := make([]byte, 20)

	_, err := ComputeCCVAndExecutorHash(ccvAddresses, executorAddr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many CCV addresses")
	assert.Contains(t, err.Error(), "256")
	assert.Contains(t, err.Error(), "max 255")

	// Verify that exactly MaxCCVsPerMessage works
	ccvAddressesMax := make([]UnknownAddress, MaxCCVsPerMessage)
	for i := range ccvAddressesMax {
		ccvAddressesMax[i] = make([]byte, 20)
	}
	hash, err := ComputeCCVAndExecutorHash(ccvAddressesMax, executorAddr)
	require.NoError(t, err)
	assert.NotEqual(t, Bytes32{}, hash)
}
