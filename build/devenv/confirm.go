package ccv

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"

	"github.com/ethereum/go-ethereum/core/types"

	cldf_evm_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider"

	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
)

// NewConfirmFunctorAnvil specific confirmer for Anvil instant blocks.
func NewConfirmFunctorAnvil(tickInterval, waitMinedTimeout time.Duration) cldf_evm_provider.ConfirmFunctor {
	return &confirmAnvil{
		WaitMinedTimeout: waitMinedTimeout,
	}
}

type confirmAnvil struct {
	TickInterval     time.Duration
	WaitMinedTimeout time.Duration
}

func (g *confirmAnvil) Generate(
	ctx context.Context, selector uint64, client evm.OnchainClient, from common.Address,
) (evm.ConfirmFunc, error) {
	return func(tx *types.Transaction) (uint64, error) {
		var blockNum uint64
		if tx == nil {
			return 0, fmt.Errorf("tx was nil, nothing to confirm for selector: %d", selector)
		}

		ctxTimeout, cancel := context.WithTimeout(ctx, g.WaitMinedTimeout)
		defer cancel()

		receipt, err := WaitMined(ctxTimeout, client, tx.Hash())
		if err != nil {
			return 0, fmt.Errorf("tx %s failed to confirm for selector %d: %w",
				tx.Hash().Hex(), selector, err,
			)
		}
		if receipt == nil {
			return blockNum, fmt.Errorf("receipt was nil for tx %s for selector %d",
				tx.Hash().Hex(), selector,
			)
		}

		blockNum = receipt.BlockNumber.Uint64()

		if receipt.Status == 0 {
			reason, err := getErrorReasonFromTx(ctxTimeout, client, from, tx, receipt)
			if err == nil && reason != "" {
				return 0, fmt.Errorf("tx %s reverted for selector %d: %s",
					tx.Hash().Hex(), selector, reason,
				)
			}

			return blockNum, fmt.Errorf("tx %s reverted, could not decode error reason for selector %d",
				tx.Hash().Hex(), selector,
			)
		}

		return blockNum, nil
	}, nil
}

type DeployBackend interface {
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
}

func WaitMined(ctx context.Context, b DeployBackend, txHash common.Hash) (*types.Receipt, error) {
	queryTicker := time.NewTicker(50 * time.Millisecond)
	defer queryTicker.Stop()
	for {
		receipt, err := b.TransactionReceipt(ctx, txHash)
		if err == nil {
			return receipt, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-queryTicker.C:
		}
	}
}

type ContractCaller interface {
	CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}

func getErrorReasonFromTx(
	ctx context.Context,
	caller ContractCaller,
	from common.Address,
	tx *types.Transaction,
	receipt *types.Receipt,
) (string, error) {
	call := ethereum.CallMsg{
		From:     from,
		To:       tx.To(),
		Data:     tx.Data(),
		Value:    tx.Value(),
		Gas:      tx.Gas(),
		GasPrice: tx.GasPrice(),
	}

	if _, err := caller.CallContract(ctx, call, receipt.BlockNumber); err != nil {
		reason, perr := getJSONErrorData(err)
		if perr == nil {
			return reason, nil
		}
		if reason == "" {
			return err.Error(), nil
		}
	}

	return "", fmt.Errorf("tx %s reverted with no reason", tx.Hash().Hex())
}

func getJSONErrorData(err error) (string, error) {
	if err == nil {
		return "", errors.New("cannot parse nil error")
	}

	// Define a custom interface that matches the structure of the JSON error because it is a
	// private type in go-ethereum.
	//
	// https://github.com/ethereum/go-ethereum/blob/0983cd789ee1905aedaed96f72793e5af8466f34/rpc/json.go#L140
	type jsonError interface {
		Error() string
		ErrorCode() int
		ErrorData() any
	}

	var jerr jsonError
	ok := errors.As(err, &jerr)
	if !ok {
		return "", fmt.Errorf("error must be of type jsonError: %w", err)
	}

	data := fmt.Sprintf("%s", jerr.ErrorData())
	if data == "" && strings.Contains(jerr.Error(), "missing trie node") {
		return "", errors.New("missing trie node, likely due to not using an archive node")
	}

	return data, nil
}
