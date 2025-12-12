package cctp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var attestationResponseBody = []byte(`
{
  "messages": [
    {
      "message": "0xbbbbbb22",
      "eventNonce": "9682",
      "attestation": "0xaaaaaa11",
      "decodedMessage": {
        "sourceDomain": "7",
        "destinationDomain": "5",
        "nonce": "569",
        "sender": "0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350",
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

func Test_AttestationFetch_HappyPath(t *testing.T) {
	stringTxHash := "0x912f22a13e9ccb979b621500f6952b2afd6e75be7eadaed93fc2625fe11c52a2"
	txHash := mustByteSliceFromHex(stringTxHash)

	sourceChain := protocol.ChainSelector(sel.GETH_TESTNET.Selector)
	destChain := protocol.ChainSelector(sel.GETH_DEVNET_2.Selector)

	// messageID is hardcoded in the attestationResponseBody above, don't change anything in the ccipMessage
	// otherwise generated messageID won't match and the test will fail
	ccipMessage := protocol.Message{
		SourceChainSelector: sourceChain,
		DestChainSelector:   destChain,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/messages/100?transactionHash="+stringTxHash {
			_, err := w.Write(attestationResponseBody)
			require.NoError(t, err)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	attestationService, err := NewAttestationService(
		logger.Test(t),
		CCTPConfig{
			AttestationAPI:         server.URL,
			AttestationAPITimeout:  1 * time.Minute,
			AttestationAPICooldown: 5 * time.Minute,
			ParsedVerifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
				sourceChain: protocol.UnknownAddress("0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350"),
			},
		})
	require.NoError(t, err)

	attestation, err := attestationService.Fetch(t.Context(), txHash, ccipMessage)
	require.NoError(t, err)

	assert.Equal(t, "0xaaaaaa11", attestation.attestation.String())
	assert.Equal(t, "0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350", attestation.ccvAddress.String())
	assert.Equal(t, "0xbbbbbb22", attestation.encodedCCTPMessage.String())
	assert.Equal(t, "0x8e1d1a9dbbbbbb22aaaaaa11", attestation.ToVerifierFormat().String())
}

func mustByteSliceFromHex(s string) protocol.ByteSlice {
	bs, err := protocol.NewByteSliceFromHex(s)
	if err != nil {
		panic(fmt.Sprintf("failed to decode hex string: %v", err))
	}
	return bs
}
