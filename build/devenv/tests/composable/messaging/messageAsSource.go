package messaging

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"

	"github.com/stretchr/testify/require"
)

func TestBasicMessage(ctx context.Context, t *testing.T, srcChain cciptestinterfaces.ChainAsSource, destChain cciptestinterfaces.ChainAsDestination, fields cciptestinterfaces.MessageFields, opts cciptestinterfaces.MessageOptions, sendOption cciptestinterfaces.ChainSendOption) error {
	srcMessage, err := srcChain.BuildChainMessage(ctx, destChain.ChainSelector(), fields, opts)
	require.NoError(t, err)

	// send message using chainAsSource
	sentEvent, _, err := srcChain.SendChainMessage(ctx, destChain.ChainSelector(), srcMessage, sendOption)
	if err != nil {
		require.NoError(t, err)
	}

	_, err = srcChain.ConfirmSendOnSource(ctx, destChain.ChainSelector(), cciptestinterfaces.MessageEventKey{MessageID: sentEvent.MessageID}, 40*time.Second)
	if err != nil {
		require.NoError(t, err)
	}

	execEvent, err := destChain.ConfirmExecOnDest(ctx, srcChain.ChainSelector(), cciptestinterfaces.MessageEventKey{MessageID: sentEvent.MessageID}, 40*time.Second)
	if err != nil {
		require.NoError(t, err)
	}
	if execEvent.State != cciptestinterfaces.ExecutionStateSuccess {
		require.NoError(t, fmt.Errorf("unexpected execution state %s, return data: %x", execEvent.State, execEvent.ReturnData))
	}
	return nil
}
