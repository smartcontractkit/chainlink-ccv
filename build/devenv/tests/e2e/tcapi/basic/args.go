package basic

import (
	"time"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
)

// Args configures a basic messaging test case: V3 send/extra-args via Send, plus
// optional timeouts used in Run (ConfirmSendOnSource, AssertMessage, ConfirmExecOnDest).
type Args struct {
	Send tcapi.SendArgs
	// ConfirmSentTimeout overrides ConfirmSendOnSource when non-zero.
	ConfirmSentTimeout time.Duration
	// ConfirmExecTimeout overrides AssertMessage and ConfirmExecOnDest when non-zero.
	ConfirmExecTimeout time.Duration
}
