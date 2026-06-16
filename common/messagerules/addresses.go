package messagerules

import (
	"bytes"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func tokenAddressBytesEqual(ruleAddress string, messageToken protocol.ByteSlice) bool {
	if len(messageToken) == 0 {
		return false
	}
	ruleBytes, err := protocol.NewByteSliceFromHex(ruleAddress)
	if err != nil || len(ruleBytes) == 0 {
		return false
	}
	return addressBytesEqual(ruleBytes, messageToken)
}

func addressBytesEqual(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	return isLeftZeroPaddedExtension(a, b) || isLeftZeroPaddedExtension(b, a)
}

func isLeftZeroPaddedExtension(longer, shorter []byte) bool {
	if len(longer) <= len(shorter) {
		return false
	}
	pad := longer[:len(longer)-len(shorter)]
	for _, b := range pad {
		if b != 0 {
			return false
		}
	}
	return bytes.Equal(longer[len(longer)-len(shorter):], shorter)
}
