package evm

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

type transactionReceiptResponse struct {
	receipt *types.Receipt
	err     error
}

type stubTransactionReceiptGetter struct {
	responses []transactionReceiptResponse
	calls     int
}

func (s *stubTransactionReceiptGetter) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	response := s.responses[s.calls]
	s.calls++
	return response.receipt, response.err
}

func TestTransactionReceiptWithRetry(t *testing.T) {
	t.Parallel()

	txHash := common.HexToHash("0x1234")
	expectedReceipt := &types.Receipt{TxHash: txHash}

	t.Run("returns receipt after temporary not found responses", func(t *testing.T) {
		t.Parallel()

		client := &stubTransactionReceiptGetter{responses: []transactionReceiptResponse{
			{err: ethereum.NotFound},
			{err: ethereum.NotFound},
			{receipt: expectedReceipt},
		}}

		receipt, err := transactionReceiptWithRetry(t.Context(), client, txHash)

		require.NoError(t, err)
		require.Same(t, expectedReceipt, receipt)
		require.Equal(t, 3, client.calls)
	})

	t.Run("returns non-retryable error immediately", func(t *testing.T) {
		t.Parallel()

		expectedErr := errors.New("rpc unavailable")
		client := &stubTransactionReceiptGetter{responses: []transactionReceiptResponse{{err: expectedErr}}}

		receipt, err := transactionReceiptWithRetry(t.Context(), client, txHash)

		require.Nil(t, receipt)
		require.ErrorIs(t, err, expectedErr)
		require.Equal(t, 1, client.calls)
	})

	t.Run("stops after max retries", func(t *testing.T) {
		t.Parallel()

		client := &stubTransactionReceiptGetter{responses: []transactionReceiptResponse{
			{err: ethereum.NotFound},
			{err: ethereum.NotFound},
			{err: ethereum.NotFound},
			{err: ethereum.NotFound},
		}}

		receipt, err := transactionReceiptWithRetry(t.Context(), client, txHash)

		require.Nil(t, receipt)
		require.ErrorIs(t, err, ethereum.NotFound)
		require.LessOrEqual(t, client.calls, 4)
	})

	t.Run("stops when context is canceled", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		client := &stubTransactionReceiptGetter{responses: []transactionReceiptResponse{{err: ethereum.NotFound}}}

		receipt, err := transactionReceiptWithRetry(ctx, client, txHash)

		require.Nil(t, receipt)
		require.ErrorIs(t, err, context.Canceled)
		require.LessOrEqual(t, client.calls, 1)
	})
}
