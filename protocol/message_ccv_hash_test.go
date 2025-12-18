package protocol

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeCCVAndExecutorHash(t *testing.T) {
	t.Run("single CCV address", func(t *testing.T) {
		// Create test addresses (20 bytes each)
		ccvAddr, err := hex.DecodeString("1111111111111111111111111111111111111111")
		require.NoError(t, err)
		executorAddr, err := hex.DecodeString("2222222222222222222222222222222222222222")
		require.NoError(t, err)

		ccvAddresses := []UnknownAddress{UnknownAddress(ccvAddr)}
		executorAddress := UnknownAddress(executorAddr)

		hash, err := ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
		require.NoError(t, err)

		// Verify hash is not empty
		assert.NotEqual(t, Bytes32{}, hash)

		// Verify the encoded format
		// Expected: 0x14 (address length) + ccvAddr + executorAddr
		expectedEncoded := make([]byte, 1+20+20)
		expectedEncoded[0] = 20
		copy(expectedEncoded[1:21], ccvAddr)
		copy(expectedEncoded[21:41], executorAddr)
		expectedHash := Keccak256(expectedEncoded)

		assert.Equal(t, expectedHash[:], hash[:])
	})

	t.Run("multiple CCV addresses", func(t *testing.T) {
		ccvAddr1, err := hex.DecodeString("1111111111111111111111111111111111111111")
		require.NoError(t, err)
		ccvAddr2, err := hex.DecodeString("3333333333333333333333333333333333333333")
		require.NoError(t, err)
		executorAddr, err := hex.DecodeString("2222222222222222222222222222222222222222")
		require.NoError(t, err)

		ccvAddresses := []UnknownAddress{
			UnknownAddress(ccvAddr1),
			UnknownAddress(ccvAddr2),
		}
		executorAddress := UnknownAddress(executorAddr)

		hash, err := ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
		require.NoError(t, err)

		// Verify the encoded format
		// Expected: 0x14 (address length) + ccvAddr1 + ccvAddr2 + executorAddr
		expectedEncoded := make([]byte, 1+20+20+20)
		expectedEncoded[0] = 20
		copy(expectedEncoded[1:21], ccvAddr1)
		copy(expectedEncoded[21:41], ccvAddr2)
		copy(expectedEncoded[41:61], executorAddr)
		expectedHash := Keccak256(expectedEncoded)

		assert.Equal(t, expectedHash[:], hash[:])
	})

	t.Run("no CCV addresses", func(t *testing.T) {
		executorAddr, err := hex.DecodeString("2222222222222222222222222222222222222222")
		require.NoError(t, err)

		ccvAddresses := []UnknownAddress{}
		executorAddress := UnknownAddress(executorAddr)

		hash, err := ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
		require.NoError(t, err)

		// Verify the encoded format
		// Expected: 0x14 (address length) + executorAddr
		expectedEncoded := make([]byte, 1+20)
		expectedEncoded[0] = 20
		copy(expectedEncoded[1:21], executorAddr)
		expectedHash := Keccak256(expectedEncoded)

		assert.Equal(t, expectedHash[:], hash[:])
	})

	t.Run("CCV address length mismatch with executor", func(t *testing.T) {
		// CCV address is 20 bytes but executor is only 2 bytes - they must match
		ccvAddr, err := hex.DecodeString("1111111111111111111111111111111111111111")
		require.NoError(t, err)
		shortExecutorAddr := []byte{0x22, 0x22} // Only 2 bytes

		ccvAddresses := []UnknownAddress{UnknownAddress(ccvAddr)}
		executorAddress := UnknownAddress(shortExecutorAddr)

		_, err = ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
		assert.Error(t, err)
		// CCV address at index 0 has 20 bytes but executor has 2 bytes
		assert.Contains(t, err.Error(), "CCV address at index 0 has different length")
	})

	t.Run("mixed CCV address lengths", func(t *testing.T) {
		// First CCV is 20 bytes (matches executor), second CCV is only 2 bytes
		validCCVAddr, err := hex.DecodeString("1111111111111111111111111111111111111111")
		require.NoError(t, err)
		invalidCCVAddr := []byte{0x33, 0x33} // Only 2 bytes
		executorAddr, err := hex.DecodeString("2222222222222222222222222222222222222222")
		require.NoError(t, err)

		ccvAddresses := []UnknownAddress{UnknownAddress(validCCVAddr), UnknownAddress(invalidCCVAddr)}
		executorAddress := UnknownAddress(executorAddr)

		_, err = ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "CCV address at index 1 has different length")
	})
}

func TestMessage_ValidateCCVAndExecutorHash(t *testing.T) {
	t.Run("valid hash", func(t *testing.T) {
		ccvAddr, err := hex.DecodeString("1111111111111111111111111111111111111111")
		require.NoError(t, err)
		executorAddr, err := hex.DecodeString("2222222222222222222222222222222222222222")
		require.NoError(t, err)

		ccvAddresses := []UnknownAddress{UnknownAddress(ccvAddr)}
		executorAddress := UnknownAddress(executorAddr)

		// Compute the expected hash
		expectedHash, err := ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
		require.NoError(t, err)

		// Create a message with the hash
		message := &Message{
			CcvAndExecutorHash: expectedHash,
		}

		// Validate should pass
		err = message.ValidateCCVAndExecutorHash(ccvAddresses, executorAddress)
		assert.NoError(t, err)
	})

	t.Run("invalid hash - mismatch", func(t *testing.T) {
		ccvAddr, err := hex.DecodeString("1111111111111111111111111111111111111111")
		require.NoError(t, err)
		executorAddr, err := hex.DecodeString("2222222222222222222222222222222222222222")
		require.NoError(t, err)

		ccvAddresses := []UnknownAddress{UnknownAddress(ccvAddr)}
		executorAddress := UnknownAddress(executorAddr)

		// Create a message with a different hash
		message := &Message{
			CcvAndExecutorHash: Bytes32{0x99, 0x99}, // Wrong hash
		}

		// Validate should fail
		err = message.ValidateCCVAndExecutorHash(ccvAddresses, executorAddress)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ccvAndExecutorHash mismatch")
	})

	t.Run("zero hash", func(t *testing.T) {
		ccvAddr, err := hex.DecodeString("1111111111111111111111111111111111111111")
		require.NoError(t, err)
		executorAddr, err := hex.DecodeString("2222222222222222222222222222222222222222")
		require.NoError(t, err)

		ccvAddresses := []UnknownAddress{UnknownAddress(ccvAddr)}
		executorAddress := UnknownAddress(executorAddr)

		// Create a message with zero hash
		message := &Message{
			CcvAndExecutorHash: Bytes32{},
		}

		// Validate should fail (zero hash won't match computed hash)
		err = message.ValidateCCVAndExecutorHash(ccvAddresses, executorAddress)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ccvAndExecutorHash mismatch")
	})
}
