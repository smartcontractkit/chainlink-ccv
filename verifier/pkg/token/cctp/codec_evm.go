package cctp

import (
	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func init() {
	RegisterChainCodec(chainsel.FamilyEVM, evmCodec{})
}

// evmCodec implements ChainCodec for EVM chains: 0x-prefixed hex codecs and the EVM
// entries of the shared Circle-domain catalog in consts.go.
type evmCodec struct{}

func (evmCodec) Domain(selector protocol.ChainSelector) (uint32, bool) {
	domain, ok := Domains[uint64(selector)]
	return domain, ok
}

func (evmCodec) EncodeTxHash(txHash protocol.ByteSlice) string {
	return txHash.String()
}

func (evmCodec) DecodeAddress(address string) (protocol.UnknownAddress, error) {
	return protocol.NewUnknownAddressFromHex(address)
}
