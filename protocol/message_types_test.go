package protocol

import (
	"encoding/binary"
	"testing"
	"time"

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
		require.Equal(t, msg.Version, decoded.Version)
		require.Equal(t, msg.SourceChainSelector, decoded.SourceChainSelector)
		require.Equal(t, msg.DestChainSelector, decoded.DestChainSelector)
		require.Equal(t, msg.SequenceNumber, decoded.SequenceNumber)
		require.Equal(t, msg.OnRampAddressLength, decoded.OnRampAddressLength)
		require.Equal(t, msg.OnRampAddress, decoded.OnRampAddress)
		require.Equal(t, msg.OffRampAddressLength, decoded.OffRampAddressLength)
		require.Equal(t, msg.OffRampAddress, decoded.OffRampAddress)
		require.Equal(t, msg.Finality, decoded.Finality)
		require.Equal(t, msg.SenderLength, decoded.SenderLength)
		require.Equal(t, msg.Sender, decoded.Sender)
		require.Equal(t, msg.ReceiverLength, decoded.ReceiverLength)
		require.Equal(t, msg.Receiver, decoded.Receiver)
		require.Equal(t, msg.DestBlobLength, decoded.DestBlobLength)
		require.Equal(t, msg.DestBlob, decoded.DestBlob)
		require.Equal(t, msg.TokenTransferLength, decoded.TokenTransferLength)
		// TokenTransfer may be empty slice in input but nil after decode (or vice versa)
		require.Equal(t, len(msg.TokenTransfer), len(decoded.TokenTransfer))
		if len(msg.TokenTransfer) > 0 {
			require.Equal(t, msg.TokenTransfer, decoded.TokenTransfer)
		}
		require.Equal(t, msg.DataLength, decoded.DataLength)
		require.Equal(t, msg.Data, decoded.Data)
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
	require.Equal(t, id1, id2)

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
	require.NotEqual(t, id1, id3)
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
			require.Contains(t, err.Error(), tt.expectErr)
		})
	}
}

func TestMessageDiscoveryVersion(t *testing.T) {
	vHash := Keccak256([]byte("CCIP1.7_MessageDiscovery_Version"))
	version := vHash[:4]
	require.Equal(t, MessageDiscoveryVersion, version)
}

func TestVerifierResult_ValidateFieldsConsistent_Success(t *testing.T) {
	tests := []struct {
		name              string
		numCCVAddresses   int
		withTokenTransfer bool
		customData        []byte
		customDestBlob    []byte
	}{
		{
			name:              "valid with single CCV address",
			numCCVAddresses:   1,
			withTokenTransfer: false,
			customData:        []byte("test data"),
			customDestBlob:    []byte("test dest blob"),
		},
		{
			name:              "valid with multiple CCV addresses",
			numCCVAddresses:   3,
			withTokenTransfer: false,
			customData:        []byte("different data"),
			customDestBlob:    []byte("different blob"),
		},
		{
			name:              "valid with token transfer",
			numCCVAddresses:   2,
			withTokenTransfer: true,
			customData:        []byte("data with tokens"),
			customDestBlob:    []byte("blob with tokens"),
		},
		{
			name:              "valid with empty data and blob",
			numCCVAddresses:   1,
			withTokenTransfer: false,
			customData:        []byte{},
			customDestBlob:    []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - create random addresses
			sender, err := RandomAddress()
			require.NoError(t, err)
			receiver, err := RandomAddress()
			require.NoError(t, err)
			onRampAddr, err := RandomAddress()
			require.NoError(t, err)
			offRampAddr, err := RandomAddress()
			require.NoError(t, err)
			executorAddr, err := RandomAddress()
			require.NoError(t, err)

			// Create CCV addresses
			ccvAddresses := make([]UnknownAddress, tt.numCCVAddresses)
			for i := 0; i < tt.numCCVAddresses; i++ {
				addr, err := RandomAddress()
				require.NoError(t, err)
				ccvAddresses[i] = addr
			}

			// Compute the correct hash
			ccvAndExecutorHash, err := ComputeCCVAndExecutorHash(ccvAddresses, executorAddr)
			require.NoError(t, err)

			// Create token transfer if needed
			var tokenTransfer *TokenTransfer
			if tt.withTokenTransfer {
				tokenTransfer = NewEmptyTokenTransfer()
			}

			// Create message with correct hash
			msg, err := NewMessage(
				ChainSelector(1337),
				ChainSelector(2337),
				SequenceNumber(123),
				onRampAddr,
				offRampAddr,
				10,
				200_000,
				100_000,
				ccvAndExecutorHash,
				sender,
				receiver,
				tt.customDestBlob,
				tt.customData,
				tokenTransfer,
			)
			require.NoError(t, err)

			// Compute correct message ID
			msgID, err := msg.MessageID()
			require.NoError(t, err)

			// Create VerifierResult with consistent fields
			vr := &VerifierResult{
				MessageID:              msgID,
				Message:                *msg,
				MessageCCVAddresses:    ccvAddresses,
				MessageExecutorAddress: executorAddr,
				CCVData:                []byte("some ccv data"),
				Timestamp:              time.Now().UTC(),
				VerifierSourceAddress:  sender,
				VerifierDestAddress:    receiver,
			}

			// Execute
			err = vr.ValidateFieldsConsistent()

			// require
			require.NoError(t, err)
		})
	}
}

func TestVerifierResult_ValidateFieldsConsistent_CCVHashMismatch(t *testing.T) {
	tests := []struct {
		name                  string
		modifyCCVAddresses    bool
		modifyExecutorAddress bool
		modifyMessageHash     bool
	}{
		{
			name:                  "CCV addresses mismatch",
			modifyCCVAddresses:    true,
			modifyExecutorAddress: false,
			modifyMessageHash:     false,
		},
		{
			name:                  "executor address mismatch",
			modifyCCVAddresses:    false,
			modifyExecutorAddress: true,
			modifyMessageHash:     false,
		},
		{
			name:                  "message hash mismatch",
			modifyCCVAddresses:    false,
			modifyExecutorAddress: false,
			modifyMessageHash:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - create random addresses
			sender, err := RandomAddress()
			require.NoError(t, err)
			receiver, err := RandomAddress()
			require.NoError(t, err)
			onRampAddr, err := RandomAddress()
			require.NoError(t, err)
			offRampAddr, err := RandomAddress()
			require.NoError(t, err)
			executorAddr, err := RandomAddress()
			require.NoError(t, err)

			// Create CCV addresses
			ccvAddr1, err := RandomAddress()
			require.NoError(t, err)
			ccvAddresses := []UnknownAddress{ccvAddr1}

			// Compute the correct hash
			ccvAndExecutorHash, err := ComputeCCVAndExecutorHash(ccvAddresses, executorAddr)
			require.NoError(t, err)

			// Create message
			msg, err := NewMessage(
				ChainSelector(1337),
				ChainSelector(2337),
				SequenceNumber(123),
				onRampAddr,
				offRampAddr,
				10,
				200_000,
				100_000,
				ccvAndExecutorHash,
				sender,
				receiver,
				[]byte("test dest blob"),
				[]byte("test data"),
				nil,
			)
			require.NoError(t, err)

			// Compute correct message ID
			msgID, err := msg.MessageID()
			require.NoError(t, err)

			// Prepare addresses for VerifierResult (potentially modified)
			vrCCVAddresses := ccvAddresses
			vrExecutorAddr := executorAddr

			// Apply modifications based on test case
			if tt.modifyCCVAddresses {
				// Use a different CCV address
				differentCCV, err := RandomAddress()
				require.NoError(t, err)
				vrCCVAddresses = []UnknownAddress{differentCCV}
			}

			if tt.modifyExecutorAddress {
				// Use a different executor address
				differentExecutor, err := RandomAddress()
				require.NoError(t, err)
				vrExecutorAddr = differentExecutor
			}

			if tt.modifyMessageHash {
				// Modify the hash in the message directly
				msg.CcvAndExecutorHash = Bytes32{0xFF, 0xFF, 0xFF} // Invalid hash
			}

			// Create VerifierResult with mismatched fields
			vr := &VerifierResult{
				MessageID:              msgID,
				Message:                *msg,
				MessageCCVAddresses:    vrCCVAddresses,
				MessageExecutorAddress: vrExecutorAddr,
				CCVData:                []byte("some ccv data"),
				Timestamp:              time.Now().UTC(),
				VerifierSourceAddress:  sender,
				VerifierDestAddress:    receiver,
			}

			// Execute
			err = vr.ValidateFieldsConsistent()

			// require
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to validate ccv and executor hash")
		})
	}
}

func TestVerifierResult_ValidateFieldsConsistent_MessageIDMismatch(t *testing.T) {
	tests := []struct {
		name              string
		messageIDModifier func(Bytes32) Bytes32
	}{
		{
			name: "completely different message ID",
			messageIDModifier: func(original Bytes32) Bytes32 {
				return Bytes32{0x01, 0x02, 0x03}
			},
		},
		{
			name: "single byte difference",
			messageIDModifier: func(original Bytes32) Bytes32 {
				modified := original
				modified[0] = ^modified[0] // Flip all bits in first byte
				return modified
			},
		},
		{
			name: "zero message ID",
			messageIDModifier: func(original Bytes32) Bytes32 {
				return Bytes32{}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - create random addresses
			sender, err := RandomAddress()
			require.NoError(t, err)
			receiver, err := RandomAddress()
			require.NoError(t, err)
			onRampAddr, err := RandomAddress()
			require.NoError(t, err)
			offRampAddr, err := RandomAddress()
			require.NoError(t, err)
			executorAddr, err := RandomAddress()
			require.NoError(t, err)

			// Create CCV addresses
			ccvAddr, err := RandomAddress()
			require.NoError(t, err)
			ccvAddresses := []UnknownAddress{ccvAddr}

			// Compute the correct hash
			ccvAndExecutorHash, err := ComputeCCVAndExecutorHash(ccvAddresses, executorAddr)
			require.NoError(t, err)

			// Create message
			msg, err := NewMessage(
				ChainSelector(1337),
				ChainSelector(2337),
				SequenceNumber(123),
				onRampAddr,
				offRampAddr,
				10,
				200_000,
				100_000,
				ccvAndExecutorHash,
				sender,
				receiver,
				[]byte("test dest blob"),
				[]byte("test data"),
				nil,
			)
			require.NoError(t, err)

			// Compute correct message ID
			correctMsgID, err := msg.MessageID()
			require.NoError(t, err)

			// Create modified message ID
			wrongMsgID := tt.messageIDModifier(correctMsgID)

			// Create VerifierResult with wrong message ID
			vr := &VerifierResult{
				MessageID:              wrongMsgID,
				Message:                *msg,
				MessageCCVAddresses:    ccvAddresses,
				MessageExecutorAddress: executorAddr,
				CCVData:                []byte("some ccv data"),
				Timestamp:              time.Now().UTC(),
				VerifierSourceAddress:  sender,
				VerifierDestAddress:    receiver,
			}

			// Execute
			err = vr.ValidateFieldsConsistent()

			// require
			require.Error(t, err)
			require.Contains(t, err.Error(), "message ID mismatch")
		})
	}
}

func TestVerifierResult_ValidateFieldsConsistent_InvalidAddressLength(t *testing.T) {
	tests := []struct {
		name                  string
		executorAddressLength int
		ccvAddressLengths     []int
		expectedErrorContains string
	}{
		{
			name:                  "executor address too short",
			executorAddressLength: 19,
			ccvAddressLengths:     []int{20},
			expectedErrorContains: "executor address must be 20 bytes",
		},
		{
			name:                  "executor address too long",
			executorAddressLength: 21,
			ccvAddressLengths:     []int{20},
			expectedErrorContains: "executor address must be 20 bytes",
		},
		{
			name:                  "CCV address too short",
			executorAddressLength: 20,
			ccvAddressLengths:     []int{19},
			expectedErrorContains: "CCV address at index 0 must be 20 bytes",
		},
		{
			name:                  "CCV address too long",
			executorAddressLength: 20,
			ccvAddressLengths:     []int{21},
			expectedErrorContains: "CCV address at index 0 must be 20 bytes",
		},
		{
			name:                  "mixed invalid CCV addresses",
			executorAddressLength: 20,
			ccvAddressLengths:     []int{20, 19, 20},
			expectedErrorContains: "CCV address at index 1 must be 20 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - create random addresses
			sender, err := RandomAddress()
			require.NoError(t, err)
			receiver, err := RandomAddress()
			require.NoError(t, err)
			onRampAddr, err := RandomAddress()
			require.NoError(t, err)
			offRampAddr, err := RandomAddress()
			require.NoError(t, err)

			// Create executor address with specified length
			executorAddr := make(UnknownAddress, tt.executorAddressLength)

			// Create CCV addresses with specified lengths
			ccvAddresses := make([]UnknownAddress, len(tt.ccvAddressLengths))
			for i, length := range tt.ccvAddressLengths {
				ccvAddresses[i] = make(UnknownAddress, length)
			}

			// Use a dummy hash since we're testing validation before hash check
			dummyHash := Bytes32{}

			// Create message
			msg, err := NewMessage(
				ChainSelector(1337),
				ChainSelector(2337),
				SequenceNumber(123),
				onRampAddr,
				offRampAddr,
				10,
				200_000,
				100_000,
				dummyHash,
				sender,
				receiver,
				[]byte("test dest blob"),
				[]byte("test data"),
				nil,
			)
			require.NoError(t, err)

			// Compute message ID
			msgID, err := msg.MessageID()
			require.NoError(t, err)

			// Create VerifierResult with invalid address lengths
			vr := &VerifierResult{
				MessageID:              msgID,
				Message:                *msg,
				MessageCCVAddresses:    ccvAddresses,
				MessageExecutorAddress: executorAddr,
				CCVData:                []byte("some ccv data"),
				Timestamp:              time.Now().UTC(),
				VerifierSourceAddress:  sender,
				VerifierDestAddress:    receiver,
			}

			// Execute
			err = vr.ValidateFieldsConsistent()

			// require
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErrorContains)
		})
	}
}

func TestVerifierResult_ValidateFieldsConsistent_MessageEncodingError(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "message encoding succeeds - baseline test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - create valid addresses
			sender, err := RandomAddress()
			require.NoError(t, err)
			receiver, err := RandomAddress()
			require.NoError(t, err)
			onRampAddr, err := RandomAddress()
			require.NoError(t, err)
			offRampAddr, err := RandomAddress()
			require.NoError(t, err)
			executorAddr, err := RandomAddress()
			require.NoError(t, err)

			// Create CCV address
			ccvAddr, err := RandomAddress()
			require.NoError(t, err)
			ccvAddresses := []UnknownAddress{ccvAddr}

			// Compute correct hash
			ccvAndExecutorHash, err := ComputeCCVAndExecutorHash(ccvAddresses, executorAddr)
			require.NoError(t, err)

			// Create valid message
			msg, err := NewMessage(
				ChainSelector(1337),
				ChainSelector(2337),
				SequenceNumber(123),
				onRampAddr,
				offRampAddr,
				10,
				200_000,
				100_000,
				ccvAndExecutorHash,
				sender,
				receiver,
				[]byte("test dest blob"),
				[]byte("test data"),
				nil,
			)
			require.NoError(t, err)

			// Compute message ID
			msgID, err := msg.MessageID()
			require.NoError(t, err)

			// Create VerifierResult
			vr := &VerifierResult{
				MessageID:              msgID,
				Message:                *msg,
				MessageCCVAddresses:    ccvAddresses,
				MessageExecutorAddress: executorAddr,
				CCVData:                []byte("some ccv data"),
				Timestamp:              time.Now().UTC(),
				VerifierSourceAddress:  sender,
				VerifierDestAddress:    receiver,
			}

			// Execute
			err = vr.ValidateFieldsConsistent()

			// require - should succeed
			require.NoError(t, err)
		})
	}
}

func TestVerifierResult_ValidateFieldsConsistent_EmptyCCVAddresses(t *testing.T) {
	tests := []struct {
		name            string
		numCCVAddresses int
	}{
		{
			name:            "zero CCV addresses",
			numCCVAddresses: 0,
		},
		{
			name:            "single CCV address",
			numCCVAddresses: 1,
		},
		{
			name:            "five CCV addresses",
			numCCVAddresses: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - create random addresses
			sender, err := RandomAddress()
			require.NoError(t, err)
			receiver, err := RandomAddress()
			require.NoError(t, err)
			onRampAddr, err := RandomAddress()
			require.NoError(t, err)
			offRampAddr, err := RandomAddress()
			require.NoError(t, err)
			executorAddr, err := RandomAddress()
			require.NoError(t, err)

			// Create CCV addresses
			ccvAddresses := make([]UnknownAddress, tt.numCCVAddresses)
			for i := 0; i < tt.numCCVAddresses; i++ {
				addr, err := RandomAddress()
				require.NoError(t, err)
				ccvAddresses[i] = addr
			}

			// Compute the correct hash
			ccvAndExecutorHash, err := ComputeCCVAndExecutorHash(ccvAddresses, executorAddr)
			require.NoError(t, err)

			// Create message
			msg, err := NewMessage(
				ChainSelector(1337),
				ChainSelector(2337),
				SequenceNumber(123),
				onRampAddr,
				offRampAddr,
				10,
				200_000,
				100_000,
				ccvAndExecutorHash,
				sender,
				receiver,
				[]byte("test dest blob"),
				[]byte("test data"),
				nil,
			)
			require.NoError(t, err)

			// Compute correct message ID
			msgID, err := msg.MessageID()
			require.NoError(t, err)

			// Create VerifierResult
			vr := &VerifierResult{
				MessageID:              msgID,
				Message:                *msg,
				MessageCCVAddresses:    ccvAddresses,
				MessageExecutorAddress: executorAddr,
				CCVData:                []byte("some ccv data"),
				Timestamp:              time.Now().UTC(),
				VerifierSourceAddress:  sender,
				VerifierDestAddress:    receiver,
			}

			// Execute
			err = vr.ValidateFieldsConsistent()

			// require
			require.NoError(t, err)
		})
	}
}
