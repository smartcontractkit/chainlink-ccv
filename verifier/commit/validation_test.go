package commit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	protocol2 "github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

// TestValidateMessageErrors tests message validation error conditions.
func TestValidateMessageErrors(t *testing.T) {
	tests := []struct {
		task      *verifier.VerificationTask
		name      string
		expectErr string
		verifier  protocol2.UnknownAddress
	}{
		{
			name:      "nil_task",
			task:      nil,
			verifier:  protocol2.UnknownAddress{},
			expectErr: "verification task is nil",
		},
		{
			name: "unsupported_version",
			task: &verifier.VerificationTask{
				Message: protocol2.Message{
					Version: 99, // Unsupported version
				},
			},
			verifier:  protocol2.UnknownAddress{},
			expectErr: "unsupported message version",
		},
		{
			name: "verifier_not_found",
			task: &verifier.VerificationTask{
				Message: protocol2.Message{
					Version: protocol2.MessageVersion,
				},
				ReceiptBlobs: []protocol2.ReceiptWithBlob{
					{
						Issuer:            protocol2.UnknownAddress([]byte("different")),
						DestGasLimit:      100000, // Test gas limit
						DestBytesOverhead: 25,     // Test bytes overhead
						Blob:              []byte("blob"),
						ExtraArgs:         []byte{},
					},
				},
			},
			verifier:  protocol2.UnknownAddress([]byte("target")),
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
	sender, err := protocol2.RandomAddress()
	require.NoError(t, err)
	receiver, err := protocol2.RandomAddress()
	require.NoError(t, err)
	onRampAddr, err := protocol2.RandomAddress()
	require.NoError(t, err)
	offRampAddr, err := protocol2.RandomAddress()
	require.NoError(t, err)
	verifierAddr, err := protocol2.RandomAddress()
	require.NoError(t, err)

	message, err := protocol2.NewMessage(
		protocol2.ChainSelector(1337),
		protocol2.ChainSelector(2337),
		protocol2.Nonce(123),
		onRampAddr,
		offRampAddr,
		10,
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		protocol2.NewEmptyTokenTransfer(),
	)
	require.NoError(t, err)

	// Create verification task with matching verifier address
	task := &verifier.VerificationTask{
		Message: *message,
		ReceiptBlobs: []protocol2.ReceiptWithBlob{
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
	differentAddr, err := protocol2.RandomAddress()
	require.NoError(t, err)
	err = ValidateMessage(task, differentAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found as issuer")
}
