// Package register exists for its import side effect: it binds the EVM accessor factory and
// declared-chain coverage checker into chainaccess. It lives apart from package evm so that a
// plugin-based factory can take its place without a duplicate registration panic.
package register

import (
	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

// Importing this package makes chainaccess.NewRegistry construct the EVM factory eagerly, which
// fails when no EVM config is mounted: a process that does not run EVM chains must not import it.
// Tooling that only reads or converts EVM config imports .../accessors/evmconfig instead.
func init() {
	chainaccess.Register(chainsel.FamilyEVM, evm.CreateEVMAccessorFactory)
	chainaccess.RegisterDeclaredChainCoverageChecker(chainsel.FamilyEVM, checkDeclaredChainCoverage)
}
