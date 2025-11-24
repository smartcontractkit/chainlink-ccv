package common_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"

	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

const (
	validMessageID = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
)

var validBlob = []byte{0x01, 0x02, 0x03, 0x04}

// keccak256(0x010203041234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef).
var expectedHashForValidBlob = [32]uint8{0x5f, 0x64, 0xd6, 0x3a, 0x61, 0x92, 0xd6, 0xf6, 0x38, 0xe9, 0xa5, 0x9c, 0x73, 0x20, 0xa8, 0x5d, 0x56, 0xc5, 0x8, 0xb5, 0x10, 0x2f, 0xf2, 0x56, 0x88, 0x50, 0x2d, 0xbf, 0xab, 0xc8, 0xdd, 0x3b}

func validMessageIDBytes32(t *testing.T) protocol.Bytes32 {
	messageID, err := protocol.NewBytes32FromString(validMessageID)
	require.NoError(t, err)
	return messageID
}

func TestNewSignableHash(t *testing.T) {
	t.Run("valid input with minimum verifier blob data", func(t *testing.T) {
		hash, err := committee.NewSignableHash(validMessageIDBytes32(t), validBlob)
		require.NoError(t, err)
		require.Equal(t, expectedHashForValidBlob, hash, "hash should match expected value")
	})

	t.Run("valid input with verifier blob data longer than version", func(t *testing.T) {
		longVerifierBlobData := make([]byte, len(validBlob))
		copy(longVerifierBlobData, validBlob)
		longVerifierBlobData = append(longVerifierBlobData, 0x05, 0x06, 0x07, 0x08)

		hash, err := committee.NewSignableHash(validMessageIDBytes32(t), longVerifierBlobData)
		require.NoError(t, err)
		require.Equal(t, expectedHashForValidBlob, hash, "hash should match expected value")
	})

	t.Run("empty verifier blob data returns error", func(t *testing.T) {
		hash, err := committee.NewSignableHash(validMessageIDBytes32(t), []byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "verifier blob data not found")
		require.Equal(t, [32]byte{}, hash, "hash should be empty on error")
	})

	t.Run("nil verifier blob data returns error", func(t *testing.T) {
		hash, err := committee.NewSignableHash(validMessageIDBytes32(t), nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "verifier blob data not found")
		require.Equal(t, [32]byte{}, hash, "hash should be empty on error")
	})

	t.Run("verifier blob data with insufficient length returns error", func(t *testing.T) {
		oneByteVerifierBlobData := []byte{0x01}
		hash, err := committee.NewSignableHash(validMessageIDBytes32(t), oneByteVerifierBlobData)
		require.Error(t, err)
		require.Contains(t, err.Error(), "verifier blob data too short")
		require.Contains(t, err.Error(), "expected at least 4 bytes, got 1")
		require.Equal(t, [32]byte{}, hash, "hash should be empty on error")
	})

	t.Run("deterministic - same inputs produce same hash", func(t *testing.T) {
		hash1, err1 := committee.NewSignableHash(validMessageIDBytes32(t), validBlob)
		require.NoError(t, err1)

		hash2, err2 := committee.NewSignableHash(validMessageIDBytes32(t), validBlob)
		require.NoError(t, err2)

		require.Equal(t, hash1, hash2, "same inputs should produce identical hashes")
		require.Equal(t, expectedHashForValidBlob, hash1, "hash should match expected value")
	})

	t.Run("different message IDs produce different hashes", func(t *testing.T) {
		messageID1, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		messageID2, err := protocol.NewBytes32FromString("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321")
		require.NoError(t, err)

		hash1, err1 := committee.NewSignableHash(messageID1, validBlob)
		require.NoError(t, err1)

		hash2, err2 := committee.NewSignableHash(messageID2, validBlob)
		require.NoError(t, err2)

		require.NotEqual(t, hash1, hash2, "different message IDs should produce different hashes")
	})

	t.Run("different verifier versions produce different hashes", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		require.NoError(t, err)

		verifierBlobData1 := []byte{0x01, 0x00, 0x00, 0x00}
		verifierBlobData2 := []byte{0x02, 0x00, 0x00, 0x00}

		hash1, err1 := committee.NewSignableHash(messageID, verifierBlobData1)
		require.NoError(t, err1)

		hash2, err2 := committee.NewSignableHash(messageID, verifierBlobData2)
		require.NoError(t, err2)

		require.NotEqual(t, hash1, hash2, "different verifier versions should produce different hashes")
	})

	t.Run("error message includes message ID", func(t *testing.T) {
		messageID, err := protocol.NewBytes32FromString("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
		require.NoError(t, err)

		// Test empty blob error message
		_, err = committee.NewSignableHash(messageID, []byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")

		// Test too short blob error message
		_, err = committee.NewSignableHash(messageID, []byte{0x01})
		require.Error(t, err)
		require.Contains(t, err.Error(), "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	})
}

func TestMessageDiscoveryVersion(t *testing.T) {
	vHash := protocol.Keccak256([]byte("CCIP1.7_MessageDiscovery_Version"))
	version := vHash[:4]
	t.Logf("version: %s", hexutil.Encode(version))
	require.Equal(t, committee.MessageDiscoveryVersion, version)
}
