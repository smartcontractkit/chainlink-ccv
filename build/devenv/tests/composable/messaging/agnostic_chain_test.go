package messaging

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
)

// MessageV3TestScenario is a helper test scenario that sends a CCIP message using the ChainAsSource and ChainAsDestination interfaces.
// It uses these partial interfaces to build, send, and assert messages in a way that is reusable across different chain families.
// After a chain integration implements either ChainAsSource or ChainAsDestination, they can wire up this test scenario to verify their implementation (evmPOC_test.go is an example).
// This test scenario supports partial implementation, so an integration can implement source side FIRST, connecting it to the existing EVM destination to confirm source side functionality.
func MessageV3TestScenario(
	ctx context.Context,
	srcChain cciptestinterfaces.ChainAsSource,
	destChain cciptestinterfaces.ChainAsDestination,
	fields cciptestinterfaces.MessageFields,
	opts cciptestinterfaces.MessageOptions,
	sendOption cciptestinterfaces.ChainSendOption,
	executorArgsParams any,
	tokenArgsParams any,
	tokenReceiverParams any,
) error {
	v3Receiver, ok := destChain.(cciptestinterfaces.MessageV3Destination)
	if !ok {
		return fmt.Errorf("dest chain does not support V3 message")
	}
	v3Source, ok := srcChain.(cciptestinterfaces.MessageV3Source)
	if !ok {
		return fmt.Errorf("source chain does not support V3 message")
	}

	extraArgs, err := v3Source.BuildV3ExtraArgs(opts, v3Receiver, executorArgsParams, tokenReceiverParams, tokenArgsParams)
	if err != nil {
		return fmt.Errorf("failed to encode V3 extra args: %w", err)
	}

	srcMessage, err := srcChain.BuildChainMessage(ctx, fields, extraArgs)
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

// EVMMessageV2TestScenario is a helper test scenario that sends a CCIP message using the ChainAsSource and EVMExtraArgsV2 interfaces.
func EVMMessageV2TestScenario(
	ctx context.Context,
	source cciptestinterfaces.ChainAsSource,
	dest cciptestinterfaces.ChainAsDestination,
	fields cciptestinterfaces.MessageFields,
	opts cciptestinterfaces.EVMExtraArgsV2Data,
	sendOption cciptestinterfaces.ChainSendOption,
) error {
	v2Source, ok := source.(cciptestinterfaces.EVMExtraArgsV2)
	if !ok {
		return fmt.Errorf("source chain does not implement V2 message")
	}

	sourceExtraArgs, err := v2Source.BuildEVMExtraArgsV2(opts)
	if err != nil {
		return fmt.Errorf("failed to serialize V2 args: %w", err)
	}

	message, err := source.BuildChainMessage(ctx, fields, sourceExtraArgs)
	if err != nil {
		return fmt.Errorf("failed to build chain message: %w", err)
	}
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

func SVMMessageV2TestScenario(
	ctx context.Context,
	source cciptestinterfaces.ChainAsSource,
	dest cciptestinterfaces.ChainAsDestination,
	fields cciptestinterfaces.MessageFields,
	opts cciptestinterfaces.SVMExtraArgsV1Data,
	sendOption cciptestinterfaces.ChainSendOption,
) error {
	svmSource, ok := source.(cciptestinterfaces.SVMExtraArgsV1)
	if !ok {
		return fmt.Errorf("source chain does not implement SVM message")
	}

	sourceExtraArgs, err := svmSource.BuildSVMExtraArgsV1(opts)
	if err != nil {
		return fmt.Errorf("failed to serialize SVM args: %w", err)
	}

	message, err := source.BuildChainMessage(ctx, fields, sourceExtraArgs)
	if err != nil {
		return fmt.Errorf("failed to build chain message: %w", err)
	}
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
