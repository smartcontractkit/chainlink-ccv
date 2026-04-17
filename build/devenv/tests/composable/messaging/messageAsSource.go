package messaging

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"

	"github.com/stretchr/testify/require"
)

func TestBasicMessage(ctx context.Context, t *testing.T, srcChain chainAsSource, destChain chainAsDestination, fields cciptestinterfaces.MessageFields, opts cciptestinterfaces.MessageOptions) error {
	extraArgs := destChain.SerializeExtraArgs(opts)

	srcMessage, err := srcChain.BuildChainMessage(ctx, extraArgs, fields)
	// send message using chainAsSource
	messageID, tx, err := srcChain.SendChainMessage(ctx, destChain.ChainSelector(), srcMessage)
	if err != nil {
		require.NoError(t, err)
	}

	err = srcChain.ConfirmMessageOnSource(ctx, messageID, tx)
	require.NoError(t, err)

	execEvent, err := destChain.WaitExecStateChangeByMessageID(ctx, srcChain.ChainSelector(), messageID, 40*time.Second)
	if err != nil {
		require.NoError(t, err)
	}
	if execEvent.State != cciptestinterfaces.ExecutionStateSuccess {
		require.NoError(t, fmt.Errorf("unexpected execution state %s, return data: %x", execEvent.State, execEvent.ReturnData))
	}
	return nil
}
