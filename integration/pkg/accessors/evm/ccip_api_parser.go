package evm

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var _ chainaccess.CCIPApiParser = (*ccipAPIParser)(nil)

// ccipAPIParser parses the CCIP API's results for EVM chains. It is separate from the accessor,
// whose DecodeAddress is already the CCTP codec's and has a different signature.
type ccipAPIParser struct{}

// NewCCIPApiParser returns the EVM CCIPApiParser.
func NewCCIPApiParser() chainaccess.CCIPApiParser {
	return ccipAPIParser{}
}

// CCIPApiParser returns the EVM CCIP API parser.
func (a *accessor) CCIPApiParser() (chainaccess.CCIPApiParser, error) {
	return NewCCIPApiParser(), nil
}

// DecodeAddress parses a hex address returned by the CCIP API into its 20 bytes. It rejects other lengths.
func (ccipAPIParser) DecodeAddress(address string) (protocol.UnknownAddress, error) {
	decoded, err := protocol.NewUnknownAddressFromHex(address)
	if err != nil {
		return nil, fmt.Errorf("invalid EVM address %q: %w", address, err)
	}
	if len(decoded) != common.AddressLength {
		return nil, fmt.Errorf("invalid EVM address %q: got %d bytes, want %d", address, len(decoded), common.AddressLength)
	}
	return decoded, nil
}
