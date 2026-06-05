package token_transfer

import (
	"math/big"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
)

// Args configures a token_transfer test case.
// A zero value is valid for same-family transfers: default amount 1000 base units,
// destination balance delta equal to the transfer amount, and tcapi send/run defaults.
// Cross-family lanes typically set Send, Run, TransferAmount, and DestBalanceIncrease.
type Args struct {
	Send tcapi.SendArgs
	Run  tcapi.RunConfig
	// TransferAmount overrides the default amount (1000 base units) when non-nil.
	TransferAmount *big.Int
	// DestBalanceIncrease overrides the expected destination balance delta when non-nil
	// (e.g. when source and destination token decimals differ).
	DestBalanceIncrease *big.Int
}
