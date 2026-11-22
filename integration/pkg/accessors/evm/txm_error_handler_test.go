package evm

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/storage"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/types"
)

type recordingDiscardMetrics struct{ calls int }

func (m *recordingDiscardMetrics) IncrementDiscardedTransactions(context.Context) {
	m.calls++
}

func TestDeterministicTxErrorHandlerFreesNonceAfterFirstBroadcast(t *testing.T) {
	t.Parallel()

	for _, errorText := range []string{
		"RPC call failed: intrinsic gas too low",
		"intrinsic gas too low: gas 574980, minimum needed 678808",
		"failed with 574980 gas: insufficient gas for floor data gas cost: have 574980, want 678808",
	} {
		t.Run(errorText, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			address := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
			store := storage.NewInMemoryStoreManager(logger.Test(t), big.NewInt(11155111))
			require.NoError(t, store.Add(address))
			meta := sqlutil.JSON(`{"MessageIDs":["0xbd285f7fba23af53bd57ef9df6b3124420db800a69590c9fd97fb4cf2d34e1a3"]}`)
			for i := range 2 {
				req := &types.TxRequest{FromAddress: address, ToAddress: address, Value: big.NewInt(0)}
				if i == 0 {
					req.Meta = &meta
				}
				_, err := store.CreateTransaction(ctx, req)
				require.NoError(t, err)
			}
			tx, err := store.UpdateUnstartedTransactionWithNonce(ctx, address, 0)
			require.NoError(t, err)
			tx.AttemptCount = 1

			metrics := &recordingDiscardMetrics{}
			lggr, logs := logger.TestObserved(t, zapcore.WarnLevel)
			var reusedNonce uint64
			noTransmission, err := (deterministicTxErrorHandler{metrics: metrics}).HandleError(
				ctx, lggr, tx, errors.New(errorText), store,
				func(_ common.Address, nonce uint64) { reusedNonce = nonce },
			)
			require.NoError(t, err)
			require.True(t, noTransmission)
			require.Zero(t, reusedNonce)
			require.Equal(t, 1, metrics.calls)
			require.NotEmpty(t, logs.All())
			var messageIDs any
			for _, field := range logs.All()[0].Context {
				if field.Key == "messageIDs" {
					messageIDs = field.Interface
				}
			}
			assert.Equal(t, "[0xbd285f7fba23af53bd57ef9df6b3124420db800a69590c9fd97fb4cf2d34e1a3]", fmt.Sprint(messageIDs))

			_, count, err := store.FetchUnconfirmedTransactionAtNonceWithCount(ctx, 0, address)
			require.NoError(t, err)
			require.Zero(t, count)
			next, err := store.UpdateUnstartedTransactionWithNonce(ctx, address, 0)
			require.NoError(t, err)
			require.NotNil(t, next, "the next message must reuse the rejected transaction's nonce")
		})
	}
}

func TestDeterministicTxErrorHandlerDoesNotDiscardOtherTransactions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		attemptCount uint16
		err          error
	}{
		{name: "later attempt", attemptCount: 2, err: errors.New("intrinsic gas too low")},
		{name: "unrelated error", attemptCount: 1, err: errors.New("replacement transaction underpriced")},
		{name: "nil error", attemptCount: 1, err: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			address := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
			store := storage.NewInMemoryStoreManager(logger.Test(t), big.NewInt(11155111))
			require.NoError(t, store.Add(address))
			_, err := store.CreateTransaction(ctx, &types.TxRequest{FromAddress: address, ToAddress: address, Value: big.NewInt(0)})
			require.NoError(t, err)
			tx, err := store.UpdateUnstartedTransactionWithNonce(ctx, address, 0)
			require.NoError(t, err)
			tx.AttemptCount = tt.attemptCount

			metrics := &recordingDiscardMetrics{}
			noTransmission, err := (deterministicTxErrorHandler{metrics: metrics}).HandleError(ctx, logger.Test(t), tx, tt.err, store,
				func(common.Address, uint64) { t.Fatal("nonce must not be rewound") })
			require.NoError(t, err)
			require.False(t, noTransmission)
			require.Zero(t, metrics.calls)
			_, count, err := store.FetchUnconfirmedTransactionAtNonceWithCount(ctx, 0, address)
			require.NoError(t, err)
			require.Equal(t, 1, count)
		})
	}
}
