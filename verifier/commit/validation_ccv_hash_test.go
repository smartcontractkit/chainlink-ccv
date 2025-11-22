package commit

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

func TestValidateCCVAndExecutorHash(t *testing.T) {
	t.Run("valid ccvAndExecutorHash", func(t *testing.T) {
		// Create test addresses (20 bytes each)
		ccvAddr1, err := hex.DecodeString("1111111111111111111111111111111111111111")
		require.NoError(t, err)
		ccvAddr2, err := hex.DecodeString("3333333333333333333333333333333333333333")
		require.NoError(t, err)
		executorAddr, err := hex.DecodeString("2222222222222222222222222222222222222222")
		require.NoError(t, err)

		// Compute the expected hash
		ccvAddresses := []protocol.UnknownAddress{
			protocol.UnknownAddress(ccvAddr1),
			protocol.UnknownAddress(ccvAddr2),
		}
		executorAddress := protocol.UnknownAddress(executorAddr)
		expectedHash, err := protocol.ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
		require.NoError(t, err)

		// Create a verification task with matching receipt blobs
		task := &verifier.VerificationTask{
			Message: protocol.Message{
				Version:            protocol.MessageVersion,
				CcvAndExecutorHash: expectedHash,
			},
			ReceiptBlobs: []protocol.ReceiptWithBlob{
				{
					Issuer:            protocol.UnknownAddress(ccvAddr1),
					DestGasLimit:      100000,
					DestBytesOverhead: 25,
					Blob:              []byte("blob1"),
					ExtraArgs:         []byte{},
				},
				{
					Issuer:            protocol.UnknownAddress(ccvAddr2),
					DestGasLimit:      100000,
					DestBytesOverhead: 25,
					Blob:              []byte("blob2"),
					ExtraArgs:         []byte{},
				},
				{
					Issuer:            protocol.UnknownAddress(executorAddr),
					DestGasLimit:      100000,
					DestBytesOverhead: 25,
					Blob:              []byte{}, // Executor has empty blob
					ExtraArgs:         []byte{},
				},
			},
		}

		// Should validate successfully
		err = validateCCVAndExecutorHash(task)
		assert.NoError(t, err)
	})

	t.Run("invalid ccvAndExecutorHash - mismatch", func(t *testing.T) {
		ccvAddr, err := hex.DecodeString("1111111111111111111111111111111111111111")
		require.NoError(t, err)
		executorAddr, err := hex.DecodeString("2222222222222222222222222222222222222222")
		require.NoError(t, err)

		// Create a verification task with wrong hash
		task := &verifier.VerificationTask{
			Message: protocol.Message{
				Version:            protocol.MessageVersion,
				CcvAndExecutorHash: protocol.Bytes32{0x99, 0x99}, // Wrong hash
			},
			ReceiptBlobs: []protocol.ReceiptWithBlob{
				{
					Issuer:            protocol.UnknownAddress(ccvAddr),
					DestGasLimit:      100000,
					DestBytesOverhead: 25,
					Blob:              []byte("blob"),
					ExtraArgs:         []byte{},
				},
				{
					Issuer:            protocol.UnknownAddress(executorAddr),
					DestGasLimit:      100000,
					DestBytesOverhead: 25,
					Blob:              []byte{}, // Executor has empty blob
					ExtraArgs:         []byte{},
				},
			},
		}

		// Should fail validation
		err = validateCCVAndExecutorHash(task)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ccvAndExecutorHash mismatch")
	})

	t.Run("single CCV with executor", func(t *testing.T) {
		ccvAddr, err := hex.DecodeString("1111111111111111111111111111111111111111")
		require.NoError(t, err)
		executorAddr, err := hex.DecodeString("2222222222222222222222222222222222222222")
		require.NoError(t, err)

		// Compute the expected hash
		ccvAddresses := []protocol.UnknownAddress{protocol.UnknownAddress(ccvAddr)}
		executorAddress := protocol.UnknownAddress(executorAddr)
		expectedHash, err := protocol.ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
		require.NoError(t, err)

		task := &verifier.VerificationTask{
			Message: protocol.Message{
				Version:            protocol.MessageVersion,
				CcvAndExecutorHash: expectedHash,
			},
			ReceiptBlobs: []protocol.ReceiptWithBlob{
				{
					Issuer:            protocol.UnknownAddress(ccvAddr),
					DestGasLimit:      100000,
					DestBytesOverhead: 25,
					Blob:              []byte("blob"),
					ExtraArgs:         []byte{},
				},
				{
					Issuer:            protocol.UnknownAddress(executorAddr),
					DestGasLimit:      100000,
					DestBytesOverhead: 25,
					Blob:              []byte{}, // Executor has empty blob
					ExtraArgs:         []byte{},
				},
			},
		}

		err = validateCCVAndExecutorHash(task)
		assert.NoError(t, err)
	})

	t.Run("no receipt blobs", func(t *testing.T) {
		task := &verifier.VerificationTask{
			Message: protocol.Message{
				Version:            protocol.MessageVersion,
				CcvAndExecutorHash: protocol.Bytes32{0x11, 0x22},
			},
			ReceiptBlobs: []protocol.ReceiptWithBlob{},
		}

		err := validateCCVAndExecutorHash(task)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no receipt blobs")
	})
}

func TestValidateMessage_WithCCVAndExecutorHash(t *testing.T) {
	t.Run("zero hash skips validation", func(t *testing.T) {
		verifierAddr, err := protocol.RandomAddress()
		require.NoError(t, err)
		defaultExecutorAddr, err := protocol.RandomAddress()
		require.NoError(t, err)

		task := &verifier.VerificationTask{
			Message: protocol.Message{
				Version:            protocol.MessageVersion,
				CcvAndExecutorHash: protocol.Bytes32{}, // Zero hash
			},
			ReceiptBlobs: []protocol.ReceiptWithBlob{
				{
					Issuer:            verifierAddr,
					DestGasLimit:      100000,
					DestBytesOverhead: 25,
					Blob:              []byte("blob"),
					ExtraArgs:         []byte{},
				},
			},
		}

		// Should fail validation (zero hash is required)
		err = ValidateMessage(task, verifierAddr, defaultExecutorAddr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ccvAndExecutorHash is required and cannot be zero")
	})

	t.Run("non-zero hash is validated", func(t *testing.T) {
		ccvAddr, err := hex.DecodeString("1111111111111111111111111111111111111111")
		require.NoError(t, err)
		executorAddr, err := hex.DecodeString("2222222222222222222222222222222222222222")
		require.NoError(t, err)

		// Compute correct hash
		ccvAddresses := []protocol.UnknownAddress{protocol.UnknownAddress(ccvAddr)}
		executorAddress := protocol.UnknownAddress(executorAddr)
		correctHash, err := protocol.ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
		require.NoError(t, err)

		task := &verifier.VerificationTask{
			Message: protocol.Message{
				Version:            protocol.MessageVersion,
				CcvAndExecutorHash: correctHash,
			},
			ReceiptBlobs: []protocol.ReceiptWithBlob{
				{
					Issuer:            protocol.UnknownAddress(ccvAddr),
					DestGasLimit:      100000,
					DestBytesOverhead: 25,
					Blob:              []byte("blob"),
					ExtraArgs:         []byte{},
				},
				{
					Issuer:            protocol.UnknownAddress(executorAddr),
					DestGasLimit:      100000,
					DestBytesOverhead: 25,
					Blob:              []byte{}, // Executor has empty blob
					ExtraArgs:         []byte{},
				},
			},
		}

		// Should pass validation
		err = ValidateMessage(task, protocol.UnknownAddress(ccvAddr), protocol.UnknownAddress(executorAddr))
		assert.NoError(t, err)
	})
}
