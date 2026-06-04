package token_transfer

import (
	"math/big"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
)

// Args configures a token_transfer test case: V3 send/extra-args via Send, plus
// transfer amounts and timeouts used in Run (balance checks and ConfirmExecOnDest).
type Args struct {
	Send tcapi.SendArgs
	// TransferAmount overrides the default amount (1000 base units) when non-nil.
	TransferAmount *big.Int
	// DestBalanceIncrease overrides the expected destination balance delta when non-nil
	// (e.g. when source and destination token decimals differ).
	DestBalanceIncrease *big.Int
	// ConfirmExecTimeout overrides ConfirmExecOnDest and AssertMessage timeouts when non-zero.
	ConfirmExecTimeout time.Duration
}
