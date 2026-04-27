package messaging

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
)

// MessageV3TestScenario is a helper test scenario that sends a CCIP message using the ChainAsSource and ChainAsDestination interfaces.
// It uses these partial interfaces to build, send, and assert messages in a way that is reusable across different chain families.
// After a chain integration implements either ChainAsSource or ChainAsDestination, they can wire up this test scenario to verify their implementation (evmPOC_test.go is an example).
// This test scenario supports partial implementation, so an integration can implement source side FIRST, connecting it to the existing EVM destination to confirm source side functionality.
func MessageV3TestScenario(
	ctx context.Context,
	t *testing.T,
	srcChain cciptestinterfaces.ChainAsSource,
	destChain cciptestinterfaces.ChainAsDestination,
	fields cciptestinterfaces.MessageFields,
	opts cciptestinterfaces.MessageOptions,
	sendOption cciptestinterfaces.ChainSendOption,
	executorArgsParams any,
	tokenArgsParams any,
) error {
	v3Receiver, ok := destChain.(cciptestinterfaces.MessageV3Destination)
	if !ok {
		return fmt.Errorf("dest chain does not support V3 message")
	}
	v3Serializer, ok := srcChain.(cciptestinterfaces.MessageV3Source)
	if !ok {
		return fmt.Errorf("source chain does not support V3 message")
	}
	// provider, err := destChain.ExtraArgsBuilder(extraArgsOptions...)
	// if err != nil {
	// 	return fmt.Errorf("failed to build extra args: %w", err)
	// }
	// extraArgs, err := srcChain.SerializeExtraArgs(provider)
	// if err != nil {
	// 	return fmt.Errorf("failed to serialize extra args: %w", err)
	// }

	execArgs, err := v3Receiver.GetExecutorArgs(executorArgsParams)
	if err != nil {
		return fmt.Errorf("failed to get executor args: %w", err)
	}
	tokenArgs, err := v3Receiver.GetTokenArgs(tokenArgsParams)
	if err != nil {
		return fmt.Errorf("failed to get token args: %w", err)
	}
	extraArgs, err := v3Serializer.SerializeMessageV3ExtraArgs(cciptestinterfaces.MessageOptions{
		FinalityConfig:      opts.FinalityConfig,
		ExecutionGasLimit:   opts.ExecutionGasLimit,
		Executor:            opts.Executor,
		ExecutorArgs:        execArgs,
		TokenArgs:           tokenArgs,
		CCVs:                opts.CCVs,
		OutOfOrderExecution: opts.OutOfOrderExecution,
	})
	if err != nil {
		return fmt.Errorf("failed to encode V3 extra args: %w", err)
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

func MessageV2TestScenario(
	ctx context.Context,
	t *testing.T,
	source cciptestinterfaces.ChainAsSource,
	dest cciptestinterfaces.ChainAsDestination,
	fields cciptestinterfaces.MessageFields,
	opts cciptestinterfaces.Any2EVMMessageV2Data,
	sendOption cciptestinterfaces.ChainSendOption,
) error {
	v2Source, ok := source.(cciptestinterfaces.Any2EVMMessageV2)
	if !ok {
		return fmt.Errorf("source chain does not implement V2 message")
	}
	sourceExtraArgs, err := v2Source.SerializeAny2EVMMessageV2(opts)
	if err != nil {
		return fmt.Errorf("failed to build V3 args: %w", err)
	}

	message, err := source.BuildChainMessage(ctx, dest.ChainSelector(), fields, sourceExtraArgs)
	messageSentEvent, _, err := source.SendChainMessage(ctx, dest.ChainSelector(), message, sendOption)
	if err != nil {
		return fmt.Errorf("failed to send chain message: %w", err)
	}
	sentEvent, err := source.ConfirmSendOnSource(ctx, dest.ChainSelector(), cciptestinterfaces.MessageEventKey{MessageID: messageSentEvent.MessageID}, 40*time.Second)
	if err != nil {
		return fmt.Errorf("failed to confirm send on source: %w", err)
	}

	execEvent, err := dest.ConfirmExecOnDest(ctx, source.ChainSelector(), cciptestinterfaces.MessageEventKey{MessageID: sentEvent.MessageID}, 40*time.Second)
	if err != nil {
		return fmt.Errorf("failed to confirm exec on dest: %w", err)
	}
	if execEvent.State != cciptestinterfaces.ExecutionStateSuccess {
		return fmt.Errorf("unexpected execution state %s, return data: %x", execEvent.State, execEvent.ReturnData)
	}
	return nil
}
