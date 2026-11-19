package evm

import (
	"bytes"
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/latest/erc20"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

var balanceMonitorERC20ABI = evmtypes.MustGetABI(erc20.ERC20ABI)

// erc20DecimalsClient caches only the token decimals response needed by the balance monitor's Start.
// Preflighting before construction prevents a decimals failure from leaving upstream's worker unable to close.
type erc20DecimalsClient struct {
	client.Client
	tokenAddress common.Address
	calldata     []byte
	response     []byte
}

func newERC20DecimalsClient(ctx context.Context, cl client.Client, tokenAddress common.Address) (client.Client, error) {
	caller, err := erc20.NewERC20Caller(tokenAddress, cl)
	if err != nil {
		return nil, fmt.Errorf("create ERC-20 caller: %w", err)
	}
	decimals, err := caller.Decimals(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, fmt.Errorf("read ERC-20 decimals: %w", err)
	}
	method := balanceMonitorERC20ABI.Methods["decimals"]
	response, err := method.Outputs.Pack(decimals)
	if err != nil {
		return nil, fmt.Errorf("encode ERC-20 decimals: %w", err)
	}
	return &erc20DecimalsClient{Client: cl, tokenAddress: tokenAddress, calldata: method.ID, response: response}, nil
}

func (c *erc20DecimalsClient) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	if blockNumber == nil && msg.To != nil && *msg.To == c.tokenAddress && bytes.Equal(msg.Data, c.calldata) {
		return bytes.Clone(c.response), nil
	}
	return c.Client.CallContract(ctx, msg, blockNumber)
}
