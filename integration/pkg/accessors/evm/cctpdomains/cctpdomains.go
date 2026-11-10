// Package cctpdomains exists for its import side effect: it registers the EVM built-in CCTP domain
// table so the token verifier's config validation can check EVM chains offline. Only the token
// verifier binary imports it; it is separate from evm/register so other services do not carry it.
package cctpdomains

import (
	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/cctp"
)

func init() {
	cctp.RegisterBaseDomainTable(chainsel.FamilyEVM, func(selector protocol.ChainSelector) (uint32, bool) {
		return evm.CCTPDomain(uint64(selector))
	})
}
