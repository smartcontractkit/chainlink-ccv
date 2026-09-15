package cctp

import (
	"fmt"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// ChainAdapter holds the chain-family-specific CCTP knowledge the verifier needs: the
// Circle domain of a source chain, and the codecs for that chain's native transaction
// hash and address encodings.
//
// One adapter exists per chain family. The EVM adapter lives in this package; other
// families register theirs from their own module (see
// github.com/smartcontractkit/chainlink-ccip-solana/pkg/cctp for Solana). The verifier
// resolves the adapter from the source chain's family, so the core path holds no
// chain-specific branch.
type ChainAdapter interface {
	// Domain returns the Circle CCTP domain for the source chain selector.
	Domain(selector protocol.ChainSelector) (uint32, bool)
	// EncodeTxHash renders a source transaction hash in the format Circle's API expects.
	EncodeTxHash(txHash protocol.ByteSlice) (string, error)
	// DecodeAddress parses an address Circle returned for the source chain.
	DecodeAddress(address string) (protocol.UnknownAddress, error)
}

var adapters = make(map[string]ChainAdapter)

// RegisterAdapter registers the adapter for one chain family. It panics on a nil or
// duplicate registration: both are programming errors, and registration runs in init
// before any verifier starts.
func RegisterAdapter(selectorFamily string, adapter ChainAdapter) {
	if adapter == nil {
		panic(fmt.Sprintf("cctp: nil ChainAdapter for chain family %q", selectorFamily))
	}
	if _, exists := adapters[selectorFamily]; exists {
		panic(fmt.Sprintf("cctp: ChainAdapter already registered for chain family %q", selectorFamily))
	}
	adapters[selectorFamily] = adapter
}

// AdapterFor returns the adapter for the chain family of the given source chain selector.
func AdapterFor(selector protocol.ChainSelector) (ChainAdapter, error) {
	selectorFamily, err := chainsel.GetSelectorFamily(uint64(selector))
	if err != nil {
		return nil, fmt.Errorf("resolve chain family for selector %d: %w", selector, err)
	}
	adapter, ok := adapters[selectorFamily]
	if !ok {
		return nil, fmt.Errorf("no CCTP chain adapter registered for chain family %q (selector %d)", selectorFamily, selector)
	}
	return adapter, nil
}
