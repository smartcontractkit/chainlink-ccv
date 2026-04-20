package evm

import (
	"context"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type EVMOptions interface {
	// GetRoundRobinUser returns a function that yields the next round-robin transact opts for the chain.
	GetRoundRobinUser() func() *bind.TransactOpts
	// GetUserNonce returns the nonce for the given user address on this chain.
	GetUserNonce(ctx context.Context, userAddress protocol.UnknownAddress) (uint64, error)
}

type EVMSendOptions struct {
	Nonce                 *uint64
	Sender                *bind.TransactOpts
	UseTestRouter         bool
	ValidateTokenBalances bool
}

type IEVMSendOptions interface {
	cciptestinterfaces.ChainSendOption
	WithEVMSendOptions() *EVMSendOptions
}

func (o EVMSendOptions) IsSendOption() bool { return true }
func WithEVMSendOptions(nonce *uint64, sender *bind.TransactOpts, validateTokenBalances bool) cciptestinterfaces.ChainSendOption {
	return EVMSendOptions{
		Nonce:                 nonce,
		Sender:                sender,
		ValidateTokenBalances: validateTokenBalances,
		UseTestRouter:         false,
	}
}
