package commit

import (
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/verifier/types"
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
)

// TestReceiptBlobDecodingErrors tests receipt blob decoding error conditions
func TestReceiptBlobDecodingErrors(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		expectErr string
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

// TestSignatureEncodingErrors tests signature encoding error conditions
func TestSignatureEncodingErrors(t *testing.T) {
	tests := []struct {
		name      string
		rs        [][32]byte
		ss        [][32]byte
		expectErr string
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

// TestValidateMessageErrors tests message validation error conditions
func TestValidateMessageErrors(t *testing.T) {
	tests := []struct {
		name      string
		task      *types.VerificationTask
		verifier  common.UnknownAddress
		expectErr string
	}{
		{
			name:      "nil_task",
			task:      nil,
			verifier:  common.UnknownAddress{},
			expectErr: "verification task is nil",
		},
		{
			name: "unsupported_version",
			task: &types.VerificationTask{
				Message: common.Message{
					Version: 99, // Unsupported version
				},
			},
			verifier:  common.UnknownAddress{},
			expectErr: "unsupported message version",
		},
		{
			name: "verifier_not_found",
			task: &types.VerificationTask{
				Message: common.Message{
					Version: common.MessageVersion,
				},
				ReceiptBlobs: []common.ReceiptWithBlob{
					{
						Issuer: common.UnknownAddress([]byte("different")),
						Blob:   []byte("blob"),
					},
				},
			},
			verifier:  common.UnknownAddress([]byte("target")),
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

// TestValidateMessage tests message validation with valid cases
func TestValidateMessage(t *testing.T) {
	sender, err := common.RandomAddress()
	require.NoError(t, err)
	receiver, err := common.RandomAddress()
	require.NoError(t, err)
	onRampAddr, err := common.RandomAddress()
	require.NoError(t, err)
	offRampAddr, err := common.RandomAddress()
	require.NoError(t, err)
	verifierAddr, err := common.RandomAddress()
	require.NoError(t, err)

	message := common.NewMessage(
		cciptypes.ChainSelector(1337),
		cciptypes.ChainSelector(2337),
		cciptypes.SeqNum(123),
		onRampAddr,
		offRampAddr,
		10,
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		common.NewEmptyTokenTransfer(),
	)

	// Create verification task with matching verifier address
	task := &types.VerificationTask{
		Message: *message,
		ReceiptBlobs: []common.ReceiptWithBlob{
			{
				Issuer: verifierAddr,
				Blob:   []byte("test blob"),
			},
		},
	}

	// Should validate successfully
	err = ValidateMessage(task, verifierAddr)
	assert.NoError(t, err)

	// Should fail with different verifier address
	differentAddr, err := common.RandomAddress()
	require.NoError(t, err)
	err = ValidateMessage(task, differentAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found as issuer")
}
