package cctp

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/fake"
)

var attestationResponseBody = `
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
}`

type AttestationAPI struct {
	mu sync.RWMutex
}

func NewAttestationAPI() *AttestationAPI {
	return &AttestationAPI{}
}

func (a *AttestationAPI) Register() error {
	return fake.Func("GET", "/cctp/v2/messages/100", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, attestationResponseBody)
	})
}
