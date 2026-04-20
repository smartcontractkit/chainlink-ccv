package evm

import (
	"context"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// EVMOptions provides EVM-specific capabilities not part of the generic Chain interface.
type EVMOptions interface {
	// GetRoundRobinUser returns a function that yields the next round-robin transact opts for the chain. This is evm specific because the return type is of type *bind.TransactOpts.
	GetRoundRobinUser() func() *bind.TransactOpts
	// GetUserNonce returns the nonce for the given user address on this chain.
	GetUserNonce(ctx context.Context, userAddress protocol.UnknownAddress) (uint64, error)
}

// SendOptions is the ChainSendOption implementation for EVM chains.
// These are the options developers can pass to the SendChainMessage method to customize the send behavior for a single message.
type SendOptions struct {
	Nonce                        *uint64
	Sender                       *bind.TransactOpts
	UseTestRouter                bool
	DisableTokenAmountValidation bool
}

// SendOptionsAccessor is the evm side of the ChainSendOption interface.
// It is used to access the SendOptions struct from the evm implementation.
type SendOptionsAccessor interface {
	// Defining IsSendOption allows the evm implementation to satisfy the ChainSendOption interface so it can be passed as to the SendChainMessage method.
	cciptestinterfaces.ChainSendOption
	// WithEVMSendOptions is used as an example to show how SendOptions can be used and passed to the SendChainMessage method.
	WithEVMSendOptions() *SendOptions
}

func (o SendOptions) IsSendOption() bool { return true }

// WithEVMSendOptions is a convenience method to create a sendOptions struct.
// Not strictly required, but it demonstrates how altVMs can add their own chain specific logic to the SendChainMessage method.
func WithEVMSendOptions(nonce *uint64, sender *bind.TransactOpts, disableTokenAmountValidation bool) cciptestinterfaces.ChainSendOption {
	return SendOptions{
		Nonce:                        nonce,
		Sender:                       sender,
		DisableTokenAmountValidation: disableTokenAmountValidation,
		UseTestRouter:                false,
	}
}
