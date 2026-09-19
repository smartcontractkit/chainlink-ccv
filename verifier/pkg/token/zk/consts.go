package zk

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// DefaultVerifierVersionHex is the default hex-encoded version of the SuccinctZKVerifier contract (with 0x prefix).
// bytes4(keccak256("SuccinctZKVerifier 0.0.1-dev")).
const DefaultVerifierVersionHex = "0x31d46054"

// DefaultVerifierVersion is the version of the SuccinctZKVerifier contract.
var DefaultVerifierVersion = mustDecodeHex(DefaultVerifierVersionHex)

const (
	// verifierVersionBytes is the length of the version tag the contract reads in front of the witness.
	verifierVersionBytes  = 4
	messageSentTopicCount = 4
	messageIDTopicIndex   = 3
)

// CCIPMessageSentTopic is keccak256 of the OnRamp event signature
// CCIPMessageSent(uint64,address,bytes32,address,uint256,bytes,(address,uint32,uint32,uint256,bytes)[],bytes[]).
var CCIPMessageSentTopic = common.HexToHash("0x371bc2ff0a006f4ef863b1d27a065d4e9f938b6d883eb154572b4aea593b32cc")

func mustDecodeHex(s string) protocol.ByteSlice {
	b, err := protocol.NewByteSliceFromHex(s)
	if err != nil {
		panic(fmt.Sprintf("failed to decode hex: %v", err))
	}
	return b
}
