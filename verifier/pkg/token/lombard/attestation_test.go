package lombard

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/internal"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	hash1 = "0x117f49bfccd85ce2d0ad3a2c9bc27af2abd43eed0cbaeb2ddf5098cbd6bb8bcf"
	hash2 = "0x27bf6eb2920da82a6a1294ceff503733c5a46a36d6d6c56a006f8720c399574b"
	hash3 = "0x5455ad825ac854ec2bfee200961d62ea57269bd248b782ed727ab33fd698e061"
	hash4 = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
)

const response = `{
				"attestations": [
					{
						"message_hash": "` + hash1 + `",
						"attestation": "0xdata1",
						"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
					},
					{
						"message_hash": "` + hash2 + `",
						"attestation": "0xdata2",
						"status": "NOTARIZATION_STATUS_PENDING"
					},
					{
						"message_hash": "` + hash3 + `",
						"attestation": "0xdata3",
						"status": "NOTARIZATION_STATUS_FAILED"
					}
				]
			}`

func Test_AttestationFetch(t *testing.T) {
	sourceChain := protocol.ChainSelector(sel.GETH_TESTNET.Selector)
	resolverAddress := internal.MustUnknownAddressFromHex("0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350")

	// Create verification tasks with ReceiptBlobs containing the hashes
	task1 := createTestTask(sourceChain, 1, resolverAddress, internal.MustByteSliceFromHex(hash1))
	task2 := createTestTask(sourceChain, 2, resolverAddress, internal.MustByteSliceFromHex(hash2))
	task3 := createTestTask(sourceChain, 3, resolverAddress, internal.MustByteSliceFromHex(hash3))
	task4 := createTestTask(sourceChain, 4, resolverAddress, internal.MustByteSliceFromHex(hash4))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bridge/v1/deposits/getByHash" {
			_, err := w.Write([]byte(response))
			require.NoError(t, err)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	attestationService, err := NewAttestationService(
		logger.Test(t),
		LombardConfig{
			AttestationAPI:        server.URL,
			AttestationAPITimeout: 1 * time.Minute,
			ParsedVerifierResolvers: map[protocol.ChainSelector]protocol.UnknownAddress{
				sourceChain: resolverAddress,
			},
		})
	require.NoError(t, err)

	t.Run("successful single message fetch", func(t *testing.T) {
		attestation, err := attestationService.Fetch(t.Context(), []verifier.VerificationTask{task1})
		require.NoError(t, err)

		assert.Len(t, attestation, 1)
		attestationPayload, ok := attestation[task1.MessageID]
		require.True(t, ok)
		assert.True(t, attestationPayload.IsReady())
		assert.Equal(t, "0xdata1", attestationPayload.attestation)
	})

	t.Run("successful fetch for multiple messages with not ready state", func(t *testing.T) {
		attestation, err := attestationService.Fetch(t.Context(), []verifier.VerificationTask{task2, task3})
		require.NoError(t, err)

		assert.Len(t, attestation, 2)
		for _, task := range []verifier.VerificationTask{task2, task3} {
			attestationPayload, ok := attestation[task.MessageID]
			require.True(t, ok)
			assert.False(t, attestationPayload.IsReady())
		}
	})

	t.Run("return unspecified status for unknown message", func(t *testing.T) {
		attestation, err := attestationService.Fetch(t.Context(), []verifier.VerificationTask{task4})
		require.NoError(t, err)

		assert.Len(t, attestation, 1)
		attestationPayload, ok := attestation[task4.MessageID]
		require.True(t, ok)
		assert.False(t, attestationPayload.IsReady())
		assert.Equal(t, AttestationStatusUnspecified, attestationPayload.status)
	})

	t.Run("skip task with no matching receipt blob", func(t *testing.T) {
		taskWithoutMatchingBlob := createTestTaskWithoutMatchingBlob(sourceChain, 5)

		attestation, err := attestationService.Fetch(t.Context(), []verifier.VerificationTask{taskWithoutMatchingBlob})
		require.NoError(t, err)

		// Should still return a result with missing attestation
		assert.Len(t, attestation, 1)
		attestationPayload, ok := attestation[taskWithoutMatchingBlob.MessageID]
		require.True(t, ok)
		assert.False(t, attestationPayload.IsReady())
		assert.Equal(t, AttestationStatusUnspecified, attestationPayload.status)
	})

	t.Run("skip task with empty ReceiptBlobs", func(t *testing.T) {
		taskWithEmptyReceipts := createTestTaskWithEmptyReceipts(sourceChain, 6)

		attestation, err := attestationService.Fetch(t.Context(), []verifier.VerificationTask{taskWithEmptyReceipts})
		require.NoError(t, err)

		// Should still return a result with missing attestation
		assert.Len(t, attestation, 1)
		attestationPayload, ok := attestation[taskWithEmptyReceipts.MessageID]
		require.True(t, ok)
		assert.False(t, attestationPayload.IsReady())
		assert.Equal(t, AttestationStatusUnspecified, attestationPayload.status)
	})

	t.Run("handle mixed tasks with and without matching blobs", func(t *testing.T) {
		taskWithoutMatchingBlob := createTestTaskWithoutMatchingBlob(sourceChain, 7)
		taskWithEmptyReceipts := createTestTaskWithEmptyReceipts(sourceChain, 8)

		// Mix of valid and invalid tasks
		tasks := []verifier.VerificationTask{task1, taskWithoutMatchingBlob, task2, taskWithEmptyReceipts}

		attestation, err := attestationService.Fetch(t.Context(), tasks)
		require.NoError(t, err)

		// Should return attestations for all tasks
		assert.Len(t, attestation, 4)

		// Valid tasks should have their attestations
		attestation1, ok := attestation[task1.MessageID]
		require.True(t, ok)
		assert.True(t, attestation1.IsReady())
		assert.Equal(t, "0xdata1", attestation1.attestation)

		attestation2, ok := attestation[task2.MessageID]
		require.True(t, ok)
		assert.False(t, attestation2.IsReady())
		assert.Equal(t, AttestationStatusPending, attestation2.status)

		// Invalid tasks should have missing attestations
		attestationMissing1, ok := attestation[taskWithoutMatchingBlob.MessageID]
		require.True(t, ok)
		assert.False(t, attestationMissing1.IsReady())
		assert.Equal(t, AttestationStatusUnspecified, attestationMissing1.status)

		attestationMissing2, ok := attestation[taskWithEmptyReceipts.MessageID]
		require.True(t, ok)
		assert.False(t, attestationMissing2.IsReady())
		assert.Equal(t, AttestationStatusUnspecified, attestationMissing2.status)
	})

	t.Run("all tasks without matching blobs", func(t *testing.T) {
		taskWithoutMatchingBlob1 := createTestTaskWithoutMatchingBlob(sourceChain, 9)
		taskWithoutMatchingBlob2 := createTestTaskWithoutMatchingBlob(sourceChain, 10)

		tasks := []verifier.VerificationTask{taskWithoutMatchingBlob1, taskWithoutMatchingBlob2}

		attestation, err := attestationService.Fetch(t.Context(), tasks)
		require.NoError(t, err)

		// Should return missing attestations for all tasks
		assert.Len(t, attestation, 2)
		for _, task := range tasks {
			attestationPayload, ok := attestation[task.MessageID]
			require.True(t, ok)
			assert.False(t, attestationPayload.IsReady())
			assert.Equal(t, AttestationStatusUnspecified, attestationPayload.status)
		}
	})
}

// Helper function to create a test verification task with a matching receipt blob.
func createTestTask(sourceChain protocol.ChainSelector, seqNum int, resolverAddress protocol.UnknownAddress, blob protocol.ByteSlice) verifier.VerificationTask {
	msg := protocol.Message{
		SourceChainSelector: sourceChain,
		DestChainSelector:   protocol.ChainSelector(sel.ETHEREUM_MAINNET.Selector),
		SequenceNumber:      protocol.SequenceNumber(seqNum),
	}

	return verifier.VerificationTask{
		MessageID: msg.MustMessageID().String(),
		Message:   msg,
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			{Issuer: internal.CCVAddress1, Blob: []byte("ccv1-blob")},
			{Issuer: resolverAddress, Blob: blob}, // Matching blob
			{Issuer: internal.ExecutorAddress, Blob: []byte("executor-blob")},
			{Issuer: internal.RouterAddress, Blob: []byte("router-blob")},
		},
	}
}

// Helper function to create a test verification task without a matching receipt blob.
func createTestTaskWithoutMatchingBlob(sourceChain protocol.ChainSelector, seqNum int) verifier.VerificationTask {
	msg := protocol.Message{
		SourceChainSelector: sourceChain,
		DestChainSelector:   protocol.ChainSelector(sel.ETHEREUM_MAINNET.Selector),
		SequenceNumber:      protocol.SequenceNumber(seqNum),
	}

	// Different issuer that doesn't match resolverAddress
	differentIssuer := internal.MustUnknownAddressFromHex("0xffffffffffffffffffffffffffffffffffffffff")

	return verifier.VerificationTask{
		MessageID: msg.MustMessageID().String(),
		Message:   msg,
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			{Issuer: internal.CCVAddress1, Blob: []byte("ccv1-blob")},
			{Issuer: differentIssuer, Blob: []byte("some-other-blob")}, // Non-matching issuer
			{Issuer: internal.ExecutorAddress, Blob: []byte("executor-blob")},
			{Issuer: internal.RouterAddress, Blob: []byte("router-blob")},
		},
	}
}

// Helper function to create a test verification task with empty receipt blobs.
func createTestTaskWithEmptyReceipts(sourceChain protocol.ChainSelector, seqNum int) verifier.VerificationTask {
	msg := protocol.Message{
		SourceChainSelector: sourceChain,
		DestChainSelector:   protocol.ChainSelector(sel.ETHEREUM_MAINNET.Selector),
		SequenceNumber:      protocol.SequenceNumber(seqNum),
	}

	return verifier.VerificationTask{
		MessageID:    msg.MustMessageID().String(),
		Message:      msg,
		ReceiptBlobs: []protocol.ReceiptWithBlob{}, // Empty receipt blobs
	}
}

func Test_ToVerifierFormat(t *testing.T) {
	verifierVersion := protocol.ByteSlice{0x01, 0x02, 0x03, 0x04}

	// Helper function to ABI encode payload and proof
	encodeAttestationData := func(rawPayload, proof []byte) ([]byte, error) {
		bytesType, err := abi.NewType("bytes", "", nil)
		if err != nil {
			return nil, err
		}
		args := abi.Arguments{
			{Type: bytesType},
			{Type: bytesType},
		}
		return args.Pack(rawPayload, proof)
	}

	t.Run("successfully converts approved attestation to verifier format", func(t *testing.T) {
		rawPayload := []byte{0xaa, 0xbb, 0xcc, 0xdd}
		proof := []byte{0x11, 0x22, 0x33}

		attestationBytes, err := encodeAttestationData(rawPayload, proof)
		require.NoError(t, err)

		attestation := Attestation{
			verifierVersion: verifierVersion,
			attestation:     protocol.ByteSlice(attestationBytes).String(),
			status:          AttestationStatusApproved,
		}

		result, err := attestation.ToVerifierFormat()
		require.NoError(t, err)

		// Expected format: [versionTag (4)][rawPayloadLength (2)][rawPayload][proofLength (2)][proof]
		rawPayloadLength := uint16(len(rawPayload))
		proofLength := uint16(len(proof))

		expected := make(protocol.ByteSlice, 0, len(verifierVersion)+lengthPrefixBytes+len(rawPayload)+lengthPrefixBytes+len(proof))
		expected = append(expected, verifierVersion...)
		expected = append(expected, byte(rawPayloadLength>>8), byte(rawPayloadLength))
		expected = append(expected, rawPayload...)
		expected = append(expected, byte(proofLength>>8), byte(proofLength))
		expected = append(expected, proof...)

		assert.Equal(t, expected, result)
		assert.Len(t, result, 4+2+len(rawPayload)+2+len(proof))
	})

	t.Run("handles empty proof", func(t *testing.T) {
		rawPayload := []byte{0xaa, 0xbb, 0xcc, 0xdd}
		proof := []byte{}

		attestationBytes, err := encodeAttestationData(rawPayload, proof)
		require.NoError(t, err)

		attestation := Attestation{
			verifierVersion: verifierVersion,
			attestation:     protocol.ByteSlice(attestationBytes).String(),
			status:          AttestationStatusApproved,
		}

		result, err := attestation.ToVerifierFormat()
		require.NoError(t, err)

		rawPayloadLength := uint16(len(rawPayload))
		proofLength := uint16(len(proof))

		expected := make(protocol.ByteSlice, 0, len(verifierVersion)+lengthPrefixBytes+len(rawPayload)+lengthPrefixBytes)
		expected = append(expected, verifierVersion...)
		expected = append(expected, byte(rawPayloadLength>>8), byte(rawPayloadLength))
		expected = append(expected, rawPayload...)
		expected = append(expected, byte(proofLength>>8), byte(proofLength))

		assert.Equal(t, expected, result)
	})

	t.Run("handles empty payload", func(t *testing.T) {
		rawPayload := []byte{}
		proof := []byte{0x11, 0x22, 0x33}

		attestationBytes, err := encodeAttestationData(rawPayload, proof)
		require.NoError(t, err)

		attestation := Attestation{
			verifierVersion: verifierVersion,
			attestation:     protocol.ByteSlice(attestationBytes).String(),
			status:          AttestationStatusApproved,
		}

		result, err := attestation.ToVerifierFormat()
		require.NoError(t, err)

		rawPayloadLength := uint16(len(rawPayload))
		proofLength := uint16(len(proof))

		expected := make(protocol.ByteSlice, 0, len(verifierVersion)+lengthPrefixBytes+lengthPrefixBytes+len(proof))
		expected = append(expected, verifierVersion...)
		expected = append(expected, byte(rawPayloadLength>>8), byte(rawPayloadLength))
		expected = append(expected, byte(proofLength>>8), byte(proofLength))
		expected = append(expected, proof...)

		assert.Equal(t, expected, result)
	})

	t.Run("handles large payload and proof", func(t *testing.T) {
		// Create payload and proof larger than 255 bytes to test 2-byte length encoding
		rawPayload := make([]byte, 300)
		for i := range rawPayload {
			rawPayload[i] = byte(i % 256)
		}
		proof := make([]byte, 400)
		for i := range proof {
			proof[i] = byte((i + 100) % 256)
		}

		attestationBytes, err := encodeAttestationData(rawPayload, proof)
		require.NoError(t, err)

		attestation := Attestation{
			verifierVersion: verifierVersion,
			attestation:     protocol.ByteSlice(attestationBytes).String(),
			status:          AttestationStatusApproved,
		}

		result, err := attestation.ToVerifierFormat()
		require.NoError(t, err)

		rawPayloadLength := uint16(len(rawPayload))
		proofLength := uint16(len(proof))

		// Verify structure
		assert.Equal(t, verifierVersion, result[0:4])
		// Verify rawPayloadLength
		assert.Equal(t, byte(rawPayloadLength>>8), result[4])
		assert.Equal(t, byte(rawPayloadLength), result[5])
		// Verify rawPayload
		assert.Equal(t, rawPayload, []byte(result[6:6+rawPayloadLength]))
		// Verify proofLength
		proofLengthOffset := 6 + rawPayloadLength
		assert.Equal(t, byte(proofLength>>8), result[proofLengthOffset])
		assert.Equal(t, byte(proofLength), result[proofLengthOffset+1])
		// Verify proof
		assert.Equal(t, proof, []byte(result[proofLengthOffset+2:]))
	})

	t.Run("returns error when attestation is not ready", func(t *testing.T) {
		attestation := Attestation{
			verifierVersion: verifierVersion,
			attestation:     "0x1234",
			status:          AttestationStatusPending,
		}

		_, err := attestation.ToVerifierFormat()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "attestation is not ready")
	})

	t.Run("returns error for invalid hex", func(t *testing.T) {
		attestation := Attestation{
			verifierVersion: verifierVersion,
			attestation:     "not-valid-hex",
			status:          AttestationStatusApproved,
		}

		_, err := attestation.ToVerifierFormat()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode attestation hex")
	})

	t.Run("returns error for invalid ABI encoding", func(t *testing.T) {
		// Create invalid ABI data - just some random bytes
		attestation := Attestation{
			verifierVersion: verifierVersion,
			attestation:     "0x0102030405", // Not valid ABI encoding
			status:          AttestationStatusApproved,
		}

		_, err := attestation.ToVerifierFormat()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to ABI decode attestation")
	})

	t.Run("successfully converts real lombard attestation to verifier format", func(t *testing.T) {
		// Real attestation data from Lombard
		realAttestation := "0x0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000001a4e288fb4a4402fb0a3289aceac41d5260d9031d376f3a9f3ee389439558417173c1f6f6b30000000000000000000000000000000000000000000000000000000000000014000000000000000000000000a2e96f8e7de37be991ee0ac8e878ed5784350f4b000000000000000000000000ff9aef444d833bf5ebbaa40a5dff55dfa5739cd7000000000000000000000000dece515a457562d695317d6a49fee80f47d939ab00000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000a50200000000000000000000000093283b6b889c591893db0dc93bad71656d5d8923000000000000000000000000da9e8e71bb750a996af33ebb8abb18cd9eb9dc750000000000000000000000004f32ae7f112c26b109357785e5c66dc5d747fbce0000000000000000000000000000000000000000000000000000000000000001eba555885352f011e40efa3548caee5d83ae10ac2463f868d2ea2dfcf35e4ef7d37f9fab00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000040006d40d6d3681a14ef49794e254367c3fcab67797438a47c279cabc899d7ff6952ba52463aa7cd2c106e9d7101716b8b73c8ac0d925b880baa43a246a2852fee0000000000000000000000000000000000000000000000000000000000000040b3687df5e0721bd8f4a830bf655b2a8d636b1985a46c47dc2ebd487f1cc0987312c7a16ba742780bbea4aedbb0b473aa5b42f6bd7f85798f03fa5fb54fefb33a0000000000000000000000000000000000000000000000000000000000000040ace9a0dfb4f47c13cc8fc4ec107ca2f4578a4ac4280fe95573aeb58d5dc1535e5592fb20684919461f07d664d87063aebfcb3913fc0c4bc551bf1b0b46708a030000000000000000000000000000000000000000000000000000000000000040c9e14c65bdd4cb31a9480c19b3a585aecce6f4a1c0f1bcdcf218860b94ccf3bf7eef8364fa83716d6741918ae41a2c8b1c8ec13e6017eeeee303ff46b01484db"

		// Expected payload and proof extracted from the real attestation
		expectedPayload, err := protocol.NewByteSliceFromHex("0xe288fb4a4402fb0a3289aceac41d5260d9031d376f3a9f3ee389439558417173c1f6f6b30000000000000000000000000000000000000000000000000000000000000014000000000000000000000000a2e96f8e7de37be991ee0ac8e878ed5784350f4b000000000000000000000000ff9aef444d833bf5ebbaa40a5dff55dfa5739cd7000000000000000000000000dece515a457562d695317d6a49fee80f47d939ab00000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000a50200000000000000000000000093283b6b889c591893db0dc93bad71656d5d8923000000000000000000000000da9e8e71bb750a996af33ebb8abb18cd9eb9dc750000000000000000000000004f32ae7f112c26b109357785e5c66dc5d747fbce0000000000000000000000000000000000000000000000000000000000000001eba555885352f011e40efa3548caee5d83ae10ac2463f868d2ea2dfcf35e4ef7d37f9fab000000000000000000000000000000000000000000000000000000")
		require.NoError(t, err)

		expectedProof, err := protocol.NewByteSliceFromHex("0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000040006d40d6d3681a14ef49794e254367c3fcab67797438a47c279cabc899d7ff6952ba52463aa7cd2c106e9d7101716b8b73c8ac0d925b880baa43a246a2852fee0000000000000000000000000000000000000000000000000000000000000040b3687df5e0721bd8f4a830bf655b2a8d636b1985a46c47dc2ebd487f1cc0987312c7a16ba742780bbea4aedbb0b473aa5b42f6bd7f85798f03fa5fb54fefb33a0000000000000000000000000000000000000000000000000000000000000040ace9a0dfb4f47c13cc8fc4ec107ca2f4578a4ac4280fe95573aeb58d5dc1535e5592fb20684919461f07d664d87063aebfcb3913fc0c4bc551bf1b0b46708a030000000000000000000000000000000000000000000000000000000000000040c9e14c65bdd4cb31a9480c19b3a585aecce6f4a1c0f1bcdcf218860b94ccf3bf7eef8364fa83716d6741918ae41a2c8b1c8ec13e6017eeeee303ff46b01484db")
		require.NoError(t, err)

		attestation := Attestation{
			verifierVersion: verifierVersion,
			attestation:     realAttestation,
			status:          AttestationStatusApproved,
		}

		result, err := attestation.ToVerifierFormat()
		require.NoError(t, err)

		// Verify the structure of the result
		expectedPayloadLength := uint16(420)
		expectedProofLength := uint16(576)

		// Expected format: [versionTag (4)][rawPayloadLength (2)][rawPayload][proofLength (2)][proof]
		expectedLength := 4 + 2 + 420 + 2 + 576
		assert.Equal(t, expectedLength, len(result))

		// Verify version tag
		assert.Equal(t, verifierVersion, result[0:4])

		// Verify rawPayloadLength
		assert.Equal(t, byte(expectedPayloadLength>>8), result[4])
		assert.Equal(t, byte(expectedPayloadLength), result[5])

		// Verify rawPayload
		assert.Equal(t, []byte(expectedPayload), []byte(result[6:6+expectedPayloadLength]))

		// Verify proofLength
		proofLengthOffset := 6 + expectedPayloadLength
		assert.Equal(t, byte(expectedProofLength>>8), result[proofLengthOffset])
		assert.Equal(t, byte(expectedProofLength), result[proofLengthOffset+1])

		// Verify proof
		assert.Equal(t, []byte(expectedProof), []byte(result[proofLengthOffset+2:]))
	})
}
