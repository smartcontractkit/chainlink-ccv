package messaging

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
)

// BasicMessageTestScenario is a helper test scenario that sends a CCIP message using the ChainAsSource and ChainAsDestination interfaces.
// It uses these partial interfaces to build, send, and assert messages in a way that is reusable across different chain families.
// After a chain integration implements either ChainAsSource or ChainAsDestination, they can wire up this test scenario to verify their implementation (evmPOC_test.go is an example).
// This test scenario supports partial implementation, so an integration can implement source side FIRST, connecting it to the existing EVM destination to confirm source side functionality.
func BasicMessageTestScenario(
	ctx context.Context,
	t *testing.T,
	srcChain cciptestinterfaces.ChainAsSource,
	destChain cciptestinterfaces.ChainAsDestination,
	fields cciptestinterfaces.MessageFields,
	extraArgsOptions []cciptestinterfaces.ExtraArgsOption,
	sendOption cciptestinterfaces.ChainSendOption,
) error {
	provider, err := destChain.ExtraArgsBuilder(extraArgsOptions...)
	if err != nil {
		return fmt.Errorf("failed to build extra args: %w", err)
	}
	extraArgs, err := srcChain.SerializeGenericExtraArgs(provider)
	if err != nil {
		return fmt.Errorf("failed to serialize extra args: %w", err)
	}

	srcMessage, err := srcChain.BuildChainMessage(ctx, destChain.ChainSelector(), fields, extraArgs)
	if err != nil {
		return fmt.Errorf("failed to build chain message: %w", err)
	}

	// send message using chainAsSource
	sentEvent, _, err := srcChain.SendChainMessage(ctx, destChain.ChainSelector(), srcMessage, sendOption)
	if err != nil {
		return fmt.Errorf("failed to send chain message: %w", err)
	}

	_, err = srcChain.ConfirmSendOnSource(ctx, destChain.ChainSelector(), cciptestinterfaces.MessageEventKey{MessageID: sentEvent.MessageID}, 40*time.Second)
	if err != nil {
		return fmt.Errorf("failed to confirm send on source: %w", err)
	}

	execEvent, err := destChain.ConfirmExecOnDest(ctx, srcChain.ChainSelector(), cciptestinterfaces.MessageEventKey{MessageID: sentEvent.MessageID}, 40*time.Second)
	if err != nil {
		return fmt.Errorf("failed to confirm exec on dest: %w", err)
	}
	if execEvent.State != cciptestinterfaces.ExecutionStateSuccess {
		return fmt.Errorf("unexpected execution state %s, return data: %x", execEvent.State, execEvent.ReturnData)
	}
	return nil
}
