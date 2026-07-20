package chaos

import (
	"context"
	"fmt"
	"testing"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
)

// ScenarioSpec describes a chaos scenario: inject an outage, send a V3 message, assert
// offchain progress, and optionally confirm execution on the destination chain. It embeds
// tcapi.V3MsgConifg so callers set the same send/assert/exec fields as basic messaging
// tests; only Outage is chaos-specific. ExecTimeout, when zero, falls back to Assert.Timeout
// then tcapi.DefaultExecTimeout (handled by RunScenario).
type ScenarioSpec struct {
	Lib ccv.Lib
	tcapi.V3MsgConifg
	Outage OutageSpec
}

// RunScenario injects the outage, then runs the standard V3 send -> confirm-send-on-source
// -> offchain assert -> (optional) confirm-exec-on-destination pipeline via
// tcapi.RunV3MessageLifecycle. The caller must provide lib and message fields; this package
// does not filter chains by family.
func RunScenario(t *testing.T, ctx context.Context, spec ScenarioSpec) error {
	cleanup, err := InjectOutage(ctx, spec.Outage)
	if err != nil {
		return fmt.Errorf("inject outage: %w", err)
	}
	t.Cleanup(cleanup)

	// Preserve chaos behavior: exec timeout falls back to Assert.Timeout, then DefaultExecTimeout.
	if spec.ExecTimeout == 0 && spec.Assert.Timeout != 0 {
		spec.ExecTimeout = spec.Assert.Timeout
	}

	return tcapi.RunV3MessageLifecycle(ctx, spec.Lib, spec.V3MsgConifg)
}
