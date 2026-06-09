package basic

import "github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"

// Args configures a basic messaging test case.
// A zero value is valid: Send and Run use tcapi defaults
// (DefaultV3ExecutionGasLimit, DefaultSentTimeout, DefaultExecTimeout).
type Args struct {
	Send tcapi.SendArgs
	Run  tcapi.RunConfig
}
