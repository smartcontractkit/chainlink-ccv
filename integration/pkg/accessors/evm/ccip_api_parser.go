package evm

import "github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"

// The EVM accessor parses the CCIP API's results for every EVM chain, with the CCTP codec's DecodeAddress.
var _ chainaccess.CCIPAPIParser = (*accessor)(nil)

// CCIPAPIParser returns the accessor itself.
func (a *accessor) CCIPAPIParser() (chainaccess.CCIPAPIParser, error) {
	return a, nil
}
