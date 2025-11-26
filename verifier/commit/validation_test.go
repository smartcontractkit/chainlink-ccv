package commit

import (
	"encoding/hex"
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
	verifierAddr, err := protocol.RandomAddress()
	require.NoError(t, err)
	defaultExecutorAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	// Create a valid ccvAndExecutorHash using specific test addresses
	ccvAddr, err := hex.DecodeString("1111111111111111111111111111111111111111")
	require.NoError(t, err)
	executorAddr, err := hex.DecodeString("2222222222222222222222222222222222222222")
	require.NoError(t, err)

	ccvAndExecutorHash, err := protocol.ComputeCCVAndExecutorHash(
		[]protocol.UnknownAddress{protocol.UnknownAddress(ccvAddr)},
		protocol.UnknownAddress(executorAddr),
	)
	require.NoError(t, err)

	// Create a minimal message with the computed hash
	message := &protocol.Message{
		Version:              protocol.MessageVersion,
		SourceChainSelector:  1337,
		DestChainSelector:    2337,
		SequenceNumber:       123,
		Finality:             10,
		ExecutionGasLimit:    300_000,
		CcipReceiveGasLimit:  300_000,
		CcvAndExecutorHash:   ccvAndExecutorHash,
		OnRampAddressLength:  20,
		OnRampAddress:        make([]byte, 20),
		OffRampAddressLength: 20,
		OffRampAddress:       make([]byte, 20),
		SenderLength:         20,
		Sender:               make([]byte, 20),
		ReceiverLength:       20,
		Receiver:             make([]byte, 20),
		DataLength:           9,
		Data:                 []byte("test data"),
		DestBlobLength:       9,
		DestBlob:             []byte("test data"),
		TokenTransferLength:  0,
		TokenTransfer:        nil,
	}

	// Create verification task with matching CCV and executor addresses
	task := &verifier.VerificationTask{
		Message: *message,
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			{
				Issuer:            protocol.UnknownAddress(ccvAddr),
				DestGasLimit:      250000, // Test gas limit
				DestBytesOverhead: 75,     // Test bytes overhead
				Blob:              []byte("test blob"),
				ExtraArgs:         []byte("test"), // Test extra args
			},
			{
				Issuer:            protocol.UnknownAddress(executorAddr),
				DestGasLimit:      250000, // Test gas limit
				DestBytesOverhead: 75,     // Test bytes overhead
				Blob:              []byte("test blob"),
				ExtraArgs:         []byte("test"), // Test extra args
			},
		},
	}

	// Should validate successfully when verifier or executor matches an issuer
	err = ValidateMessage(task, protocol.UnknownAddress(ccvAddr), protocol.UnknownAddress(executorAddr))
	assert.NoError(t, err)

	// Should pass when verifier address matches first issuer
	err = ValidateMessage(task, protocol.UnknownAddress(ccvAddr), defaultExecutorAddr)
	assert.NoError(t, err)

	// Should pass when executor address matches second issuer
	err = ValidateMessage(task, verifierAddr, protocol.UnknownAddress(executorAddr))
	assert.NoError(t, err)

	// Should fail when neither verifier nor executor matches any issuer
	differentAddr, err := protocol.RandomAddress()
	require.NoError(t, err)
	differentExecutorAddr, err := protocol.RandomAddress()
	require.NoError(t, err)
	err = ValidateMessage(task, differentAddr, differentExecutorAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found as issuer")
}
