package commit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// TestReceiptBlobDecodingErrors tests receipt blob decoding error conditions.
func TestReceiptBlobDecodingErrors(t *testing.T) {
	tests := []struct {
		name      string
		expectErr string
		data      []byte
	}{
		{
			name:      "empty_data",
			data:      []byte{},
			expectErr: "receipt blob too short",
		},
		{
			name:      "too_short",
			data:      []byte{0}, // Less than 2 bytes for length
			expectErr: "receipt blob too short",
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

// TestSignatureEncodingErrors tests signature encoding error conditions.
func TestSignatureEncodingErrors(t *testing.T) {
	tests := []struct {
		name      string
		expectErr string
		rs        [][32]byte
		ss        [][32]byte
	}{
		{
			name:      "mismatched_lengths",
			rs:        [][32]byte{{}},
			ss:        [][32]byte{{}, {}}, // Different length
			expectErr: "rs and ss arrays must have the same length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodeSignatures(tt.rs, tt.ss)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectErr)
		})
	}
}

// TestValidateMessageErrors tests message validation error conditions.
func TestValidateMessageErrors(t *testing.T) {
	tests := []struct {
		task      *types.VerificationTask
		name      string
		expectErr string
		verifier  protocol.UnknownAddress
	}{
		{
			name:      "nil_task",
			task:      nil,
			verifier:  protocol.UnknownAddress{},
			expectErr: "verification task is nil",
		},
		{
			name: "unsupported_version",
			task: &types.VerificationTask{
				Message: protocol.Message{
					Version: 99, // Unsupported version
				},
			},
			verifier:  protocol.UnknownAddress{},
			expectErr: "unsupported message version",
		},
		{
			name: "verifier_not_found",
			task: &types.VerificationTask{
				Message: protocol.Message{
					Version: protocol.MessageVersion,
				},
				ReceiptBlobs: []protocol.ReceiptWithBlob{
					{
						Issuer:            protocol.UnknownAddress([]byte("different")),
						DestGasLimit:      100000, // Test gas limit
						DestBytesOverhead: 25,     // Test bytes overhead
						Blob:              []byte("blob"),
						ExtraArgs:         []byte{},
					},
				},
			},
			verifier:  protocol.UnknownAddress([]byte("target")),
			expectErr: "not found as issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMessage(tt.task, tt.verifier)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectErr)
		})
	}
}

// TestValidateMessage tests message validation with valid cases.
func TestValidateMessage(t *testing.T) {
	sender, err := pkg.RandomAddress()
	require.NoError(t, err)
	receiver, err := pkg.RandomAddress()
	require.NoError(t, err)
	onRampAddr, err := pkg.RandomAddress()
	require.NoError(t, err)
	offRampAddr, err := pkg.RandomAddress()
	require.NoError(t, err)
	verifierAddr, err := pkg.RandomAddress()
	require.NoError(t, err)

	message, err := protocol.NewMessage(
		protocol.ChainSelector(1337),
		protocol.ChainSelector(2337),
		protocol.Nonce(123),
		onRampAddr,
		offRampAddr,
		10,
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		protocol.NewEmptyTokenTransfer(),
	)
	require.NoError(t, err)

	// Create verification task with matching verifier address
	task := &types.VerificationTask{
		Message: *message,
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			{
				Issuer:            verifierAddr,
				DestGasLimit:      250000, // Test gas limit
				DestBytesOverhead: 75,     // Test bytes overhead
				Blob:              []byte("test blob"),
				ExtraArgs:         []byte("test"), // Test extra args
			},
		},
	}

	// Should validate successfully
	err = ValidateMessage(task, verifierAddr)
	assert.NoError(t, err)

	// Should fail with different verifier address
	differentAddr, err := pkg.RandomAddress()
	require.NoError(t, err)
	err = ValidateMessage(task, differentAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found as issuer")
}
