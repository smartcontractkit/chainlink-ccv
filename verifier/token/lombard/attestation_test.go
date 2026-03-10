package lombard

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/internal"
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
