package messaging

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type genericChain interface {
	ChainSelector() uint64
}

type chainAsDestination interface {
	WithExtraArgs(opts cciptestinterfaces.MessageOptions) []byte
	GetEOAReceiverAddress() (protocol.UnknownAddress, error)
	WaitExecStateChangeByMessageID(ctx context.Context, from uint64, messageID protocol.Bytes32, timeout time.Duration) (cciptestinterfaces.ExecutionStateChangedEvent, error)
	genericChain
}

// T is router.clientEVM2AnyMessage or router.clientSolana2AnyMessage
type chainAsSource[T any] interface {
	BuildChainMessage(fields cciptestinterfaces.MessageFields, extraArgs []byte) (T, error)
	SendChainMessage(ctx context.Context, destChain uint64, message T) (protocol.Bytes32, protocol.ByteSlice, error)
	ConfirmMessageOnSourceChain(ctx context.Context, messageID protocol.Bytes32, tx protocol.ByteSlice) error
	genericChain
}
