package lombard

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// DefaultVerifierVersionHex is the default hex-encoded version of the 2.0 LombardVerifier contract (with 0x prefix).
// bytes4(keccak256("LombardVerifier 2.1.0")).
const DefaultVerifierVersionHex = "0x5b9253ce"

// DefaultVerifierVersion is the version of the 2.0 LombardVerifier contract.
var DefaultVerifierVersion = mustDecodeHex(DefaultVerifierVersionHex)

func mustDecodeHex(s string) protocol.ByteSlice {
	b, err := protocol.NewByteSliceFromHex(s)
	if err != nil {
		panic(fmt.Sprintf("failed to decode hex: %v", err))
	}
	return b
}
