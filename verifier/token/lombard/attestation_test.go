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

	msg1 := protocol.Message{
		TokenTransfer: &protocol.TokenTransfer{
			ExtraData:       internal.MustByteSliceFromHex(hash1),
			ExtraDataLength: 32,
		},
	}
	msg2 := protocol.Message{
		TokenTransfer: &protocol.TokenTransfer{
			ExtraData:       internal.MustByteSliceFromHex(hash2),
			ExtraDataLength: 32,
		},
	}
	msg3 := protocol.Message{
		TokenTransfer: &protocol.TokenTransfer{
			ExtraData:       internal.MustByteSliceFromHex(hash3),
			ExtraDataLength: 32,
		},
	}
	msg4 := protocol.Message{
		TokenTransfer: &protocol.TokenTransfer{
			ExtraData:       internal.MustByteSliceFromHex(hash4),
			ExtraDataLength: 32,
		},
	}

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
				sourceChain: internal.MustUnknownAddressFromHex("0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350"),
			},
		})
	require.NoError(t, err)

	t.Run("successful single message fetch", func(t *testing.T) {
		attestation, err := attestationService.Fetch(t.Context(), []protocol.Message{msg1})
		require.NoError(t, err)

		assert.Len(t, attestation, 1)
		attestationPayload, ok := attestation[msg1.MustMessageID().String()]
		require.True(t, ok)
		assert.True(t, attestationPayload.IsReady())
		assert.Equal(t, "0xdata1", attestationPayload.attestation)
	})

	t.Run("successful fetch for multiple messages with not ready state", func(t *testing.T) {
		attestation, err := attestationService.Fetch(t.Context(), []protocol.Message{msg2, msg3})
		require.NoError(t, err)

		assert.Len(t, attestation, 2)
		for _, msg := range []protocol.Message{msg2, msg3} {
			attestationPayload, ok := attestation[msg.MustMessageID().String()]
			require.True(t, ok)
			assert.False(t, attestationPayload.IsReady())
		}
	})

	t.Run("return unspecified status for unknown message", func(t *testing.T) {
		attestation, err := attestationService.Fetch(t.Context(), []protocol.Message{msg4})
		require.NoError(t, err)

		assert.Len(t, attestation, 1)
		attestationPayload, ok := attestation[msg4.MustMessageID().String()]
		require.True(t, ok)
		assert.False(t, attestationPayload.IsReady())
		assert.Equal(t, AttestationStatusUnspecified, attestationPayload.status)
	})

	t.Run("skip message with nil TokenTransfer", func(t *testing.T) {
		msgWithoutTokenTransfer := protocol.Message{
			SourceChainSelector: sourceChain,
			DestChainSelector:   protocol.ChainSelector(sel.ETHEREUM_MAINNET.Selector),
			SequenceNumber:      1,
			TokenTransfer:       nil, // No token transfer
		}

		attestation, err := attestationService.Fetch(t.Context(), []protocol.Message{msgWithoutTokenTransfer})
		require.NoError(t, err)

		// Should still return a result with missing attestation
		assert.Len(t, attestation, 1)
		attestationPayload, ok := attestation[msgWithoutTokenTransfer.MustMessageID().String()]
		require.True(t, ok)
		assert.False(t, attestationPayload.IsReady())
		assert.Equal(t, AttestationStatusUnspecified, attestationPayload.status)
	})

	t.Run("skip message with empty ExtraData", func(t *testing.T) {
		msgWithEmptyExtraData := protocol.Message{
			SourceChainSelector: sourceChain,
			DestChainSelector:   protocol.ChainSelector(sel.ETHEREUM_MAINNET.Selector),
			SequenceNumber:      2,
			TokenTransfer: &protocol.TokenTransfer{
				ExtraData:       nil, // Empty extra data
				ExtraDataLength: 0,
			},
		}

		attestation, err := attestationService.Fetch(t.Context(), []protocol.Message{msgWithEmptyExtraData})
		require.NoError(t, err)

		// Should still return a result with missing attestation
		assert.Len(t, attestation, 1)
		attestationPayload, ok := attestation[msgWithEmptyExtraData.MustMessageID().String()]
		require.True(t, ok)
		assert.False(t, attestationPayload.IsReady())
		assert.Equal(t, AttestationStatusUnspecified, attestationPayload.status)
	})

	t.Run("handle mixed messages with and without token transfers", func(t *testing.T) {
		msgWithoutTokenTransfer := protocol.Message{
			SourceChainSelector: sourceChain,
			DestChainSelector:   protocol.ChainSelector(sel.ETHEREUM_MAINNET.Selector),
			SequenceNumber:      3,
			TokenTransfer:       nil,
		}
		msgWithEmptyExtraData := protocol.Message{
			SourceChainSelector: sourceChain,
			DestChainSelector:   protocol.ChainSelector(sel.ETHEREUM_MAINNET.Selector),
			SequenceNumber:      4,
			TokenTransfer: &protocol.TokenTransfer{
				ExtraData:       protocol.ByteSlice{},
				ExtraDataLength: 0,
			},
		}

		// Mix of valid and invalid messages
		messages := []protocol.Message{msg1, msgWithoutTokenTransfer, msg2, msgWithEmptyExtraData}

		attestation, err := attestationService.Fetch(t.Context(), messages)
		require.NoError(t, err)

		// Should return attestations for all messages
		assert.Len(t, attestation, 4)

		// Valid messages should have their attestations
		attestation1, ok := attestation[msg1.MustMessageID().String()]
		require.True(t, ok)
		assert.True(t, attestation1.IsReady())
		assert.Equal(t, "0xdata1", attestation1.attestation)

		attestation2, ok := attestation[msg2.MustMessageID().String()]
		require.True(t, ok)
		assert.False(t, attestation2.IsReady())
		assert.Equal(t, AttestationStatusPending, attestation2.status)

		// Invalid messages should have missing attestations
		attestationMissing1, ok := attestation[msgWithoutTokenTransfer.MustMessageID().String()]
		require.True(t, ok)
		assert.False(t, attestationMissing1.IsReady())
		assert.Equal(t, AttestationStatusUnspecified, attestationMissing1.status)

		attestationMissing2, ok := attestation[msgWithEmptyExtraData.MustMessageID().String()]
		require.True(t, ok)
		assert.False(t, attestationMissing2.IsReady())
		assert.Equal(t, AttestationStatusUnspecified, attestationMissing2.status)
	})

	t.Run("all messages without token transfers", func(t *testing.T) {
		msgWithoutTokenTransfer1 := protocol.Message{
			SourceChainSelector: sourceChain,
			DestChainSelector:   protocol.ChainSelector(sel.ETHEREUM_MAINNET.Selector),
			SequenceNumber:      5,
			TokenTransfer:       nil,
		}
		msgWithoutTokenTransfer2 := protocol.Message{
			SourceChainSelector: sourceChain,
			DestChainSelector:   protocol.ChainSelector(sel.ETHEREUM_MAINNET.Selector),
			SequenceNumber:      6,
			TokenTransfer:       nil,
		}

		messages := []protocol.Message{msgWithoutTokenTransfer1, msgWithoutTokenTransfer2}

		attestation, err := attestationService.Fetch(t.Context(), messages)
		require.NoError(t, err)

		// Should return missing attestations for all messages
		assert.Len(t, attestation, 2)
		for _, msg := range messages {
			attestationPayload, ok := attestation[msg.MustMessageID().String()]
			require.True(t, ok)
			assert.False(t, attestationPayload.IsReady())
			assert.Equal(t, AttestationStatusUnspecified, attestationPayload.status)
		}
	})
}
