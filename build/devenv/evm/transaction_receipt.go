package evm

import (
	"context"
	"errors"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/sethvargo/go-retry"
)

const (
	transactionReceiptBaseInterval = time.Second
	transactionReceiptMaxRetries   = 3
)

var transactionReceiptRetryableErrors = []error{
	ethereum.NotFound,
}

type transactionReceiptGetter interface {
	TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error)
}

func transactionReceiptWithRetry(
	ctx context.Context,
	client transactionReceiptGetter,
	txHash common.Hash,
) (*types.Receipt, error) {
	backoff := retry.WithMaxRetries(transactionReceiptMaxRetries, retry.NewExponential(transactionReceiptBaseInterval))

	var receipt *types.Receipt
	err := retry.Do(ctx, backoff, func(ctx context.Context) error {
		var err error
		receipt, err = client.TransactionReceipt(ctx, txHash)
		if err != nil {
			for _, re := range transactionReceiptRetryableErrors {
				if errors.Is(err, re) {
					return retry.RetryableError(err)
				}
			}
		}
		return err
	})
	return receipt, err
}
