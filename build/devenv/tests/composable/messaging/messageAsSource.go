package messaging

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
)

func BasicMessageTestScenario(
	ctx context.Context,
	t *testing.T,
	srcChain cciptestinterfaces.ChainAsSource,
	destChain cciptestinterfaces.ChainAsDestination,
	fields cciptestinterfaces.MessageFields,
	opts cciptestinterfaces.MessageOptions,
	sendOption cciptestinterfaces.ChainSendOption,
) error {
	srcMessage, err := srcChain.BuildChainMessage(ctx, destChain.ChainSelector(), fields, opts)
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
