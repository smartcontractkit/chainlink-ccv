package cctp

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

var attestationResponseBody = []byte(`
{
  "messages": [
	{
      "message": "0xcccccc22",
      "eventNonce": "9681",
      "attestation": "0xaaaaaa22",
      "decodedMessage": {
        "sourceDomain": "7",
        "destinationDomain": "5",
        "nonce": "569",
        "sender": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
        "recipient": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
        "destinationCaller": "0xf2Edb1Ad445C6abb1260049AcDDCA9E84D7D8aaA",
        "messageBody": "0x00000000000000050000000300000000000194c2a65fc943419a5ad590042fd67c9791fd015acf53a54cc823edb8ff81b9ed722e00000000000000000000000019330d10d9cc8751218eaf51e8885d058642e08a000000000000000000000000fc05ad74c6fe2e7046e091d6ad4f660d2a15976200000000c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d610000000000000000000000002d475f4746419c83be23056309a8e2ac33b30e3b0000000000000000000000000000000000000000000000000000000002b67df0feae5e08f5e6bf04d8c1de7dada9235c56996f4420b14371d6c6f3ddd2f2da78",
        "decodedMessageBody": {
          "burnToken": "0x4Bc078D75390C0f5CCc3e7f59Ae2159557C5eb85",
          "mintRecipient": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
          "amount": "5000",
          "messageSender": "0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350",
 		  "hookData": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        }
      },
      "cctpVersion": "2",
      "status": "complete"
    },
    {
      "message": "0xbbbbbb22",
      "eventNonce": "9682",
      "attestation": "0xaaaaaa11",
      "decodedMessage": {
        "sourceDomain": "7",
        "destinationDomain": "5",
        "nonce": "569",
        "sender": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
        "recipient": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
        "destinationCaller": "0xf2Edb1Ad445C6abb1260049AcDDCA9E84D7D8aaA",
        "messageBody": "0x00000000000000050000000300000000000194c2a65fc943419a5ad590042fd67c9791fd015acf53a54cc823edb8ff81b9ed722e00000000000000000000000019330d10d9cc8751218eaf51e8885d058642e08a000000000000000000000000fc05ad74c6fe2e7046e091d6ad4f660d2a15976200000000c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d610000000000000000000000002d475f4746419c83be23056309a8e2ac33b30e3b0000000000000000000000000000000000000000000000000000000002b67df0feae5e08f5e6bf04d8c1de7dada9235c56996f4420b14371d6c6f3ddd2f2da78",
        "decodedMessageBody": {
          "burnToken": "0x4Bc078D75390C0f5CCc3e7f59Ae2159557C5eb85",
          "mintRecipient": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
          "amount": "5000",
          "messageSender": "0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350",
 		  "hookData": "0x8e1d1a9d27ef33516b82274412e89de14ddc7788847fb81282bbe5d37e6f00dee150c2f3"
        }
      },
      "cctpVersion": "2",
      "status": "complete"
    }
  ]
}`)

func Test_AttestationFetch(t *testing.T) {
	stringTxHash := "0x912f22a13e9ccb979b621500f6952b2afd6e75be7eadaed93fc2625fe11c52a2"
	txHash := internal.MustByteSliceFromHex(stringTxHash)

	sourceChain := protocol.ChainSelector(sel.GETH_TESTNET.Selector)
	destChain := protocol.ChainSelector(sel.GETH_DEVNET_2.Selector)

	// messageID is hardcoded in the attestationResponseBody above, don't change anything in the ccipMessage
	// otherwise generated messageID won't match and the test will fail
	ccipMessage := protocol.Message{
		SourceChainSelector: sourceChain,
		DestChainSelector:   destChain,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/v2/messages/100"
		expectedQuery := "transactionHash=" + stringTxHash
		if r.URL.Path == expectedPath && r.URL.RawQuery == expectedQuery {
			_, err := w.Write(attestationResponseBody)
			require.NoError(t, err)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	attestationService, err := NewAttestationService(
		logger.Test(t),
		CCTPConfig{
			AttestationAPI:         server.URL,
			AttestationAPITimeout:  1 * time.Minute,
			AttestationAPICooldown: 5 * time.Minute,
			ParsedVerifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
				sourceChain: internal.MustUnknownAddressFromHex("0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350"),
			},
		})
	require.NoError(t, err)

	t.Run("successful fetch", func(t *testing.T) {
		attestation, err := attestationService.Fetch(t.Context(), txHash, ccipMessage)
		require.NoError(t, err)

		assert.Equal(t, "0xaaaaaa11", attestation.attestation)
		assert.Equal(t, "0xbbbbbb22", attestation.encodedCCTPMessage)
		bytes, err := attestation.ToVerifierFormat()
		require.NoError(t, err)
		assert.Equal(t, "0x8e1d1a9dbbbbbb22aaaaaa11", bytes.String())
	})

	t.Run("return error when no matching message found", func(t *testing.T) {
		_, err := attestationService.Fetch(
			t.Context(),
			internal.MustByteSliceFromHex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
			ccipMessage,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token data not ready")
	})
}

func TestNewAttestationErrors(t *testing.T) {
	ccvVerifierVersion := internal.MustByteSliceFromHex("0x01020304")

	testCases := []struct {
		name          string
		msg           Message
		expectedError string
	}{
		{
			name: "decode attestation failure",
			msg: Message{
				Status:      attestationStatusSuccess,
				Attestation: "0xzzqwerwwerqwer",
				Message:     "0x02",
				DecodedMessage: DecodedMessage{
					DecodedMessageBody: DecodedMessageBody{
						MessageSender: "0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350",
					},
				},
			},
			expectedError: "failed to decode attestation",
		},
		{
			name: "invalid encoded message",
			msg: Message{
				Status:      attestationStatusSuccess,
				Attestation: "0xabc123",
				Message:     "0xzz",
				DecodedMessage: DecodedMessage{
					DecodedMessageBody: DecodedMessageBody{
						MessageSender: "0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350",
					},
				},
			},
			expectedError: "failed to decode CCTP message",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			att := NewAttestation(ccvVerifierVersion, tc.msg)
			_, err := att.ToVerifierFormat()
			require.ErrorContains(t, err, tc.expectedError)
		})
	}
}

func TestAttestation_ToVerifierFormat(t *testing.T) {
	att := Attestation{
		ccvVerifierVersion: internal.MustByteSliceFromHex("0x01020304"),
		encodedCCTPMessage: "0xdeadbeef",
		attestation:        "0xcafec0ffee",
		status:             attestationStatusSuccess,
	}

	expected := "0x01020304deadbeefcafec0ffee"
	result, err := att.ToVerifierFormat()
	require.NoError(t, err)
	assert.Equal(t, expected, result.String())
}

func Test_cctpMatchesMessage(t *testing.T) {
	sourceChain := protocol.ChainSelector(sel.GETH_TESTNET.Selector)
	destChain := protocol.ChainSelector(sel.GETH_DEVNET_2.Selector)
	ccvVerifierVersion := internal.MustByteSliceFromHex("0x8e1d1a9d")

	// Create a valid CCIP message and calculate its message ID
	ccipMessage, err := protocol.NewMessage(
		sourceChain,
		destChain,
		protocol.SequenceNumber(123),
		internal.MustUnknownAddressFromHex("0x1111111111111111111111111111111111111111"),
		internal.MustUnknownAddressFromHex("0x2222222222222222222222222222222222222222"),
		10,
		200_000,
		100_000,
		protocol.Bytes32{},
		internal.MustUnknownAddressFromHex("0x3333333333333333333333333333333333333333"),
		internal.MustUnknownAddressFromHex("0x4444444444444444444444444444444444444444"),
		[]byte("test dest blob"),
		[]byte("test data"),
		nil,
	)
	require.NoError(t, err)

	// Hardcoding hooks and messageID to avoid relying on logic we testing to generate them
	hookData := "0x8e1d1a9d73fa314b5b2e7087b9ccac8eac29b001f339ff0447dff45a4924185338bffc7f"
	messageID := internal.MustByteSliceFromHex("0x73fa314b5b2e7087b9ccac8eac29b001f339ff0447dff45a4924185338bffc7f")

	calculatedMessageID, err := ccipMessage.MessageID()
	require.NoError(t, err)
	require.Equal(t, messageID.String(), calculatedMessageID.String())

	ccvAddress := internal.MustUnknownAddressFromHex("0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350")
	ccvAddresses := map[protocol.ChainSelector]protocol.UnknownAddress{
		sourceChain: ccvAddress,
	}

	testCases := []struct {
		name             string
		cctpMessage      Message
		ccipMessage      protocol.Message
		ccvAddresses     map[protocol.ChainSelector]protocol.UnknownAddress
		expectError      bool
		expectedErrorMsg string
	}{
		{
			name: "valid match",
			cctpMessage: Message{
				Message:     "0xaabbcc",
				Attestation: "0xddeeff",
				CCTPVersion: 2,
				Status:      attestationStatusSuccess,
				DecodedMessage: DecodedMessage{
					DecodedMessageBody: DecodedMessageBody{
						HookData:      hookData,
						MessageSender: "0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350",
					},
				},
			},
			ccipMessage:      *ccipMessage,
			ccvAddresses:     ccvAddresses,
			expectError:      false,
			expectedErrorMsg: "",
		},
		{
			name: "unsupported CCTP version",
			cctpMessage: Message{
				Message:     "0xaabbcc",
				Attestation: "0xddeeff",
				CCTPVersion: 1,
				Status:      attestationStatusSuccess,
				DecodedMessage: DecodedMessage{
					DecodedMessageBody: DecodedMessageBody{
						HookData:      hookData,
						MessageSender: ccvAddress.String(),
					},
				},
			},
			ccipMessage:      *ccipMessage,
			ccvAddresses:     ccvAddresses,
			expectError:      true,
			expectedErrorMsg: "unsupported CCTP version",
		},
		{
			name: "no CCV address configured for source chain",
			cctpMessage: Message{
				Message:     "0xaabbcc",
				Attestation: "0xddeeff",
				CCTPVersion: 2,
				Status:      attestationStatusSuccess,
				DecodedMessage: DecodedMessage{
					DecodedMessageBody: DecodedMessageBody{
						HookData:      hookData,
						MessageSender: ccvAddress.String(),
					},
				},
			},
			ccipMessage:      *ccipMessage,
			ccvAddresses:     map[protocol.ChainSelector]protocol.UnknownAddress{}, // Empty map
			expectError:      true,
			expectedErrorMsg: "no CCV address configured for source chain selector",
		},
		{
			name: "sender address mismatch",
			cctpMessage: Message{
				Message:     "0xaabbcc",
				Attestation: "0xddeeff",
				CCTPVersion: 2,
				Status:      attestationStatusSuccess,
				DecodedMessage: DecodedMessage{
					DecodedMessageBody: DecodedMessageBody{
						HookData:      hookData,
						MessageSender: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
					},
				},
			},
			ccipMessage:      *ccipMessage,
			ccvAddresses:     ccvAddresses,
			expectError:      true,
			expectedErrorMsg: "sender address mismatch",
		},
		{
			name: "invalid sender address hex",
			cctpMessage: Message{
				Message:     "0xaabbcc",
				Attestation: "0xddeeff",
				CCTPVersion: 2,
				Status:      attestationStatusSuccess,
				DecodedMessage: DecodedMessage{
					DecodedMessageBody: DecodedMessageBody{
						HookData:      hookData,
						MessageSender: "0xzzzz",
					},
				},
			},
			ccipMessage:      *ccipMessage,
			ccvAddresses:     ccvAddresses,
			expectError:      true,
			expectedErrorMsg: "invalid sender address",
		},
		{
			name: "invalid hook data hex",
			cctpMessage: Message{
				Message:     "0xaabbcc",
				Attestation: "0xddeeff",
				CCTPVersion: 2,
				Status:      attestationStatusSuccess,
				DecodedMessage: DecodedMessage{
					DecodedMessageBody: DecodedMessageBody{
						HookData:      "0xzzzz",
						MessageSender: ccvAddress.String(),
					},
				},
			},
			ccipMessage:      *ccipMessage,
			ccvAddresses:     ccvAddresses,
			expectError:      true,
			expectedErrorMsg: "invalid hook data",
		},
		{
			name: "hook data mismatch",
			cctpMessage: Message{
				Message:     "0xaabbcc",
				Attestation: "0xddeeff",
				CCTPVersion: 2,
				Status:      attestationStatusSuccess,
				DecodedMessage: DecodedMessage{
					DecodedMessageBody: DecodedMessageBody{
						HookData:      "0xdeadbeefcafebabe",
						MessageSender: ccvAddress.String(),
					},
				},
			},
			ccipMessage:      *ccipMessage,
			ccvAddresses:     ccvAddresses,
			expectError:      true,
			expectedErrorMsg: "hook data mismatch",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := cctpMatchesMessage(ccvVerifierVersion, tc.ccvAddresses, tc.cctpMessage, tc.ccipMessage)

			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
