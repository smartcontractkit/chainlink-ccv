// Package evm provides EVM-specific adapter implementations for the chainlink-ccv
// deployment tooling.  Import this package with a blank identifier to self-register:
//
//	import _ "github.com/smartcontractkit/chainlink-ccv/evm"
package evm

import (
	"strings"

	chainsel "github.com/smartcontractkit/chain-selectors"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

func init() {
	// Register EVM chain type so JD operations can map proto ChainType → family.
	shared.RegisterChainTypeFamily(nodev1.ChainType_CHAIN_TYPE_EVM, chainsel.FamilyEVM)

	// EVM signing addresses are hex strings: normalise to lowercase with 0x prefix.
	shared.RegisterAddressNormalizer(chainsel.FamilyEVM, func(addr string) string {
		lower := strings.ToLower(addr)
		if !strings.HasPrefix(lower, "0x") {
			return "0x" + lower
		}
		return lower
	})

	// EVM offchain and onchain adapter implementations are registered by
	// chainlink-ccip/chains/evm, which owns the EVM contract layer. Import
	// that package to ensure the adapters are registered:
	//
	//   import _ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/adapters"
}
