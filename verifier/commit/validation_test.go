package commit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

// TestValidateMessageErrors tests message validation error conditions.
func TestValidateMessageErrors(t *testing.T) {
	tests := []struct {
		task            *verifier.VerificationTask
		name            string
		expectErr       string
		verifier        protocol.UnknownAddress
		defaultExecutor protocol.UnknownAddress
	}{
		{
			name:            "nil_task",
			task:            nil,
			verifier:        protocol.UnknownAddress{},
			defaultExecutor: protocol.UnknownAddress{},
			expectErr:       "verification task is nil",
		},
		{
			name: "unsupported_version",
			task: &verifier.VerificationTask{
				Message: protocol.Message{
					Version: 99, // Unsupported version
				},
			},
			verifier:        protocol.UnknownAddress{},
			defaultExecutor: protocol.UnknownAddress{},
			expectErr:       "unsupported message version",
		},
		{
			name: "verifier_or_default_executor_not_found",
			task: &verifier.VerificationTask{
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
			verifier:        protocol.UnknownAddress([]byte("target")),
			defaultExecutor: protocol.UnknownAddress([]byte("default_executor")),
			expectErr:       "not found as issuer in any receipt blob",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMessage(tt.task, tt.verifier, tt.defaultExecutor)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectErr)
		})
	}
}

// TestValidateMessage tests message validation with valid cases.
func TestValidateMessage(t *testing.T) {
	sender, err := protocol.RandomAddress()
	require.NoError(t, err)
	receiver, err := protocol.RandomAddress()
	require.NoError(t, err)
	onRampAddr, err := protocol.RandomAddress()
	require.NoError(t, err)
	offRampAddr, err := protocol.RandomAddress()
	require.NoError(t, err)
	verifierAddr, err := protocol.RandomAddress()
	require.NoError(t, err)
	defaultExecutorAddr, err := protocol.RandomAddress()
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
	task := &verifier.VerificationTask{
		Message: *message,
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			{
				Issuer:            verifierAddr,
				DestGasLimit:      250000, // Test gas limit
				DestBytesOverhead: 75,     // Test bytes overhead
				Blob:              []byte("test blob"),
				ExtraArgs:         []byte("test"), // Test extra args
			},
			{
				Issuer:            defaultExecutorAddr,
				DestGasLimit:      250000, // Test gas limit
				DestBytesOverhead: 75,     // Test bytes overhead
				Blob:              []byte("test blob"),
				ExtraArgs:         []byte("test"), // Test extra args
			},
		},
	}

	// Should validate successfully
	err = ValidateMessage(task, verifierAddr, defaultExecutorAddr)
	assert.NoError(t, err)

	// Should pass with different verifier address and default executor address
	differentAddr, err := protocol.RandomAddress()
	require.NoError(t, err)
	err = ValidateMessage(task, differentAddr, defaultExecutorAddr)
	assert.NoError(t, err)

	// Should fail with different verifier and different executor address
	differentExecutorAddr, err := protocol.RandomAddress()
	require.NoError(t, err)
	err = ValidateMessage(task, differentAddr, differentExecutorAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found as issuer")
}
