package cctp

import (
	"fmt"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// ChainCodec holds the chain-family-specific CCTP knowledge the verifier needs: the
// Circle domain of a source chain, and the codecs for that chain's native transaction
// hash and address encodings.
//
// One codec exists per chain family. The EVM codec lives in this package; other families
// register theirs from their own module. The verifier resolves the codec from the source
// chain's family, so the core path holds no chain-specific branch.
type ChainCodec interface {
	// Domain returns the Circle CCTP domain for the source chain selector.
	Domain(selector protocol.ChainSelector) (uint32, bool)
	// EncodeTxHash renders a source transaction hash in the format Circle's API expects.
	EncodeTxHash(txHash protocol.ByteSlice) string
	// DecodeAddress parses an address Circle returned for the source chain.
	DecodeAddress(address string) (protocol.UnknownAddress, error)
}

var chainCodecs = make(map[string]ChainCodec)

// RegisterChainCodec registers the codec for one chain family. It panics on a nil or
// duplicate registration: both are programming errors, and registration runs in init
// before any verifier starts.
func RegisterChainCodec(selectorFamily string, codec ChainCodec) {
	if codec == nil {
		panic(fmt.Sprintf("cctp: nil ChainCodec for chain family %q", selectorFamily))
	}
	if _, exists := chainCodecs[selectorFamily]; exists {
		panic(fmt.Sprintf("cctp: ChainCodec already registered for chain family %q", selectorFamily))
	}
	chainCodecs[selectorFamily] = codec
}

// ChainCodecFor returns the codec for the chain family of the given source chain selector.
func ChainCodecFor(selector protocol.ChainSelector) (ChainCodec, error) {
	selectorFamily, err := chainsel.GetSelectorFamily(uint64(selector))
	if err != nil {
		return nil, fmt.Errorf("resolve chain family for selector %d: %w", selector, err)
	}
	codec, ok := chainCodecs[selectorFamily]
	if !ok {
		return nil, fmt.Errorf("no CCTP chain codec registered for chain family %q (selector %d)", selectorFamily, selector)
	}
	return codec, nil
}
