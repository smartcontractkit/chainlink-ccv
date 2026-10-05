package evm

import (
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// The EVM accessor is the CCTP chain codec for every EVM source chain.
var _ chainaccess.CCTPCodec = (*accessor)(nil)

// CCTPCodec returns the accessor itself.
func (a *accessor) CCTPCodec() (chainaccess.CCTPCodec, error) {
	return a, nil
}

// Domain returns the Circle CCTP domain for the source chain selector.
func (a *accessor) Domain(selector protocol.ChainSelector) (uint32, bool) {
	domain, ok := CCTPDomain(uint64(selector))
	return domain, ok
}

// EncodeTxHash renders a source transaction hash as 0x-prefixed hex.
func (a *accessor) EncodeTxHash(txHash protocol.ByteSlice) string {
	return txHash.String()
}

// DecodeAddress parses an address Circle returned for an EVM source chain.
func (a *accessor) DecodeAddress(address string) (protocol.UnknownAddress, error) {
	return protocol.NewUnknownAddressFromHex(address)
}
