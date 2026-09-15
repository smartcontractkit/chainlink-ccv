package cctp

import (
	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func init() {
	RegisterAdapter(chainsel.FamilyEVM, evmAdapter{})
}

// evmAdapter implements ChainAdapter for EVM chains: 0x-prefixed hex codecs and the EVM
// entries of the shared Circle-domain catalog in consts.go.
type evmAdapter struct{}

func (evmAdapter) Domain(selector protocol.ChainSelector) (uint32, bool) {
	domain, ok := Domains[uint64(selector)]
	return domain, ok
}

func (evmAdapter) EncodeTxHash(txHash protocol.ByteSlice) (string, error) {
	return txHash.String(), nil
}

func (evmAdapter) DecodeAddress(address string) (protocol.UnknownAddress, error) {
	return protocol.NewUnknownAddressFromHex(address)
}
