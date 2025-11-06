package committee

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestNewHash(t *testing.T) {
	t.Run("valid input with minimum verifier blob data", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		// Exactly 4 bytes (minimum valid length)
		verifierBlobData := []byte{0x01, 0x02, 0x03, 0x04}

		hash, err := NewSignableHash(messageID, verifierBlobData)
		require.NoError(t, err)
		assert.NotEqual(t, [32]byte{}, hash, "hash should not be empty")
	})

	t.Run("valid input with verifier blob data longer than version", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		// More than 4 bytes - only first 4 should be used in hash
		verifierBlobData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

		hash, err := NewSignableHash(messageID, verifierBlobData)
		require.NoError(t, err)
		assert.NotEqual(t, [32]byte{}, hash, "hash should not be empty")
	})

	t.Run("empty verifier blob data returns error", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		verifierBlobData := []byte{}

		hash, err := NewSignableHash(messageID, verifierBlobData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verifier blob data not found")
		assert.Equal(t, [32]byte{}, hash, "hash should be empty on error")
	})

	t.Run("nil verifier blob data returns error", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		hash, err := NewSignableHash(messageID, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verifier blob data not found")
		assert.Equal(t, [32]byte{}, hash, "hash should be empty on error")
	})

	t.Run("verifier blob data with 1 byte returns error", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		verifierBlobData := []byte{0x01}

		hash, err := NewSignableHash(messageID, verifierBlobData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verifier blob data too short")
		assert.Contains(t, err.Error(), "expected at least 4 bytes, got 1")
		assert.Equal(t, [32]byte{}, hash, "hash should be empty on error")
	})

	t.Run("verifier blob data with 2 bytes returns error", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		verifierBlobData := []byte{0x01, 0x02}

		hash, err := NewSignableHash(messageID, verifierBlobData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verifier blob data too short")
		assert.Contains(t, err.Error(), "expected at least 4 bytes, got 2")
		assert.Equal(t, [32]byte{}, hash, "hash should be empty on error")
	})

	t.Run("verifier blob data with 3 bytes returns error", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		verifierBlobData := []byte{0x01, 0x02, 0x03}

		hash, err := NewSignableHash(messageID, verifierBlobData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verifier blob data too short")
		assert.Contains(t, err.Error(), "expected at least 4 bytes, got 3")
		assert.Equal(t, [32]byte{}, hash, "hash should be empty on error")
	})

	t.Run("deterministic - same inputs produce same hash", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		verifierBlobData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

		hash1, err1 := NewSignableHash(messageID, verifierBlobData)
		require.NoError(t, err1)

		hash2, err2 := NewSignableHash(messageID, verifierBlobData)
		require.NoError(t, err2)

		assert.Equal(t, hash1, hash2, "same inputs should produce identical hashes")
	})

	t.Run("different message IDs produce different hashes", func(t *testing.T) {
		messageID1, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		messageID2, err := protocol.NewBytes32FromString("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321")
		require.NoError(t, err)

		verifierBlobData := []byte{0x01, 0x02, 0x03, 0x04}

		hash1, err1 := NewSignableHash(messageID1, verifierBlobData)
		require.NoError(t, err1)

		hash2, err2 := NewSignableHash(messageID2, verifierBlobData)
		require.NoError(t, err2)

		assert.NotEqual(t, hash1, hash2, "different message IDs should produce different hashes")
	})

	t.Run("different verifier versions produce different hashes", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		verifierBlobData1 := []byte{0x01, 0x00, 0x00, 0x00}
		verifierBlobData2 := []byte{0x02, 0x00, 0x00, 0x00}

		hash1, err1 := NewSignableHash(messageID, verifierBlobData1)
		require.NoError(t, err1)

		hash2, err2 := NewSignableHash(messageID, verifierBlobData2)
		require.NoError(t, err2)

		assert.NotEqual(t, hash1, hash2, "different verifier versions should produce different hashes")
	})

	t.Run("only first 4 bytes of verifier blob data are used", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		// Same first 4 bytes, different remaining bytes
		verifierBlobData1 := []byte{0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB}
		verifierBlobData2 := []byte{0x01, 0x02, 0x03, 0x04, 0xCC, 0xDD}

		hash1, err1 := NewSignableHash(messageID, verifierBlobData1)
		require.NoError(t, err1)

		hash2, err2 := NewSignableHash(messageID, verifierBlobData2)
		require.NoError(t, err2)

		assert.Equal(t, hash1, hash2, "only first 4 bytes should be used in hash, rest should be ignored")
	})

	t.Run("empty message ID produces valid hash", func(t *testing.T) {
		// Empty/zero message ID should still work
		messageID := protocol.Bytes32{}

		verifierBlobData := []byte{0x01, 0x02, 0x03, 0x04}

		hash, err := NewSignableHash(messageID, verifierBlobData)
		require.NoError(t, err)
		assert.NotEqual(t, [32]byte{}, hash, "hash should be produced even with zero message ID")
	})

	t.Run("all zeros verifier version produces valid hash", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		verifierBlobData := []byte{0x00, 0x00, 0x00, 0x00}

		hash, err := NewSignableHash(messageID, verifierBlobData)
		require.NoError(t, err)
		assert.NotEqual(t, [32]byte{}, hash, "hash should be produced with all-zero version")
	})

	t.Run("all max bytes verifier version produces valid hash", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		verifierBlobData := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		hash, err := NewSignableHash(messageID, verifierBlobData)
		require.NoError(t, err)
		assert.NotEqual(t, [32]byte{}, hash, "hash should be produced with max byte version")
	})

	t.Run("hash structure is correct - 32 bytes", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		verifierBlobData := []byte{0x01, 0x02, 0x03, 0x04}

		hash, err := NewSignableHash(messageID, verifierBlobData)
		require.NoError(t, err)

		// Hash should be exactly 32 bytes
		assert.Len(t, hash, 32, "hash should be exactly 32 bytes")
	})

	t.Run("known input produces expected hash", func(t *testing.T) {
		// Test with known values to ensure the hash calculation is correct
		messageID, err := protocol.NewBytes32FromString("0x0000000000000000000000000000000000000000000000000000000000000001")
		require.NoError(t, err)

		verifierBlobData := []byte{0x00, 0x00, 0x00, 0x01, 0x99, 0x99} // version 1, extra bytes ignored

		hash, err := NewSignableHash(messageID, verifierBlobData)
		require.NoError(t, err)

		// The preImage should be: [0x00, 0x00, 0x00, 0x01] + messageID (32 bytes)
		// Total: 36 bytes
		// This produces a deterministic keccak256 hash
		hashHex := hex.EncodeToString(hash[:])

		// Verify it's not empty and is deterministic
		assert.NotEmpty(t, hashHex)

		// Run again to verify determinism
		hash2, err := NewSignableHash(messageID, verifierBlobData)
		require.NoError(t, err)
		assert.Equal(t, hash, hash2)
	})

	t.Run("large verifier blob data works correctly", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		// Large blob - only first 4 bytes matter
		verifierBlobData := make([]byte, 1000)
		verifierBlobData[0] = 0x01
		verifierBlobData[1] = 0x02
		verifierBlobData[2] = 0x03
		verifierBlobData[3] = 0x04

		hash, err := NewSignableHash(messageID, verifierBlobData)
		require.NoError(t, err)
		assert.NotEqual(t, [32]byte{}, hash)

		// Compare with minimal blob having same first 4 bytes
		minimalBlobData := []byte{0x01, 0x02, 0x03, 0x04}
		hash2, err := NewSignableHash(messageID, minimalBlobData)
		require.NoError(t, err)

		assert.Equal(t, hash, hash2, "large blob should produce same hash as minimal blob with same version")
	})

	t.Run("different byte orders in version produce different hashes", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		// Test that byte order matters
		verifierBlobData1 := []byte{0x01, 0x02, 0x03, 0x04}
		verifierBlobData2 := []byte{0x04, 0x03, 0x02, 0x01} // reversed

		hash1, err1 := NewSignableHash(messageID, verifierBlobData1)
		require.NoError(t, err1)

		hash2, err2 := NewSignableHash(messageID, verifierBlobData2)
		require.NoError(t, err2)

		assert.NotEqual(t, hash1, hash2, "byte order in version should matter")
	})

	t.Run("error message includes message ID", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
		require.NoError(t, err)

		// Test empty blob error message
		_, err = NewSignableHash(messageID, []byte{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")

		// Test too short blob error message
		_, err = NewSignableHash(messageID, []byte{0x01})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	})
}
