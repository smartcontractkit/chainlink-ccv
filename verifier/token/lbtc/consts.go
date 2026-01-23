package lbtc

import (
	"encoding/hex"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// VerifierVersion is the version of the 1.7 LombardVerifier contract.
var VerifierVersion = mustDecodeHex("f0f3a135")

func mustDecodeHex(s string) protocol.ByteSlice {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("failed to decode hex: %v", err))
	}
	return protocol.ByteSlice(b)
}
