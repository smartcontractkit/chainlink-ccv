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
	SerializeExtraArgs(opts cciptestinterfaces.MessageOptions) []byte
	GetEOAReceiverAddress() (protocol.UnknownAddress, error)
	ConfirmExecOnDest(ctx context.Context, from uint64, key cciptestinterfaces.MessageEventKey, timeout time.Duration) (cciptestinterfaces.ExecutionStateChangedEvent, error)

	genericChain
}

type chainAsSource interface {
	// BuildAndSendMessage builds and sends a chain message in one step. receiver, destChain, and
	// extraArgs are required; data payload and token transfer are optional via msgOpts.
	// Implementations are responsible for any chain-family-specific send behaviour (e.g. nonce management).
	// BuildAndSendMessage(ctx context.Context, destChain uint64, receiver protocol.UnknownAddress, extraArgs []byte, msgOpts []cciptestinterfaces.BuildMessageOption) (protocol.Bytes32, protocol.ByteSlice, error)

	// BuildExtraArgs(ctx context.Context, destChain uint64, opts cciptestinterfaces.MessageOptions) ([]byte, error)

	BuildChainMessage(ctx context.Context, extraArgs []byte, messageFields cciptestinterfaces.MessageFields) (any, error)

	SendChainMessage(ctx context.Context, destChain uint64, message any) (protocol.Bytes32, protocol.ByteSlice, error)

	ConfirmSendOnSource(ctx context.Context, to uint64, key cciptestinterfaces.MessageEventKey, timeout time.Duration) (cciptestinterfaces.MessageSentEvent, error)
	genericChain
}
