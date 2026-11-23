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
	"github.com/smartcontractkit/chainlink-evm/pkg/keys/keystest"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/storage"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/types"
)

type recordingDiscardMetrics struct {
	discardCalls   int
	lifecycleCalls int
}

func (m *recordingDiscardMetrics) IncrementDiscardedTransactions(context.Context) {
	m.discardCalls++
}

func (m *recordingDiscardMetrics) IncrementLifecycleFailure(context.Context, txm.LifecycleFailureStage) {
	m.lifecycleCalls++
}

type fixedPendingNonceClient struct {
	nonce uint64
	err   error
	calls int
}

func (c *fixedPendingNonceClient) PendingNonceAt(context.Context, common.Address) (uint64, error) {
	c.calls++
	return c.nonce, c.err
}

func TestDeterministicTxErrorHandlerFreesLatestNonceAfterFirstBroadcast(t *testing.T) {
	t.Parallel()

	for _, errorText := range []string{
		"RPC call failed: intrinsic gas too low",
		"intrinsic gas too low: gas 574980, minimum needed 678808",
		"failed with 574980 gas: insufficient gas for floor data gas cost: have 574980, want 678808",
		"Intrinsic gas exceeds gas limit",
		"Transaction gas limit provided '50000' is insufficient of intrinsic gas required '60000'",
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
			tx, err := store.UpdateUnstartedTransactionWithNonce(ctx, address, 7)
			require.NoError(t, err)
			tx.AttemptCount = 1

			metrics := &recordingDiscardMetrics{}
			client := &fixedPendingNonceClient{nonce: 7}
			lggr, logs := logger.TestObserved(t, zapcore.WarnLevel)
			var reusedAddress common.Address
			reusedNonce := uint64(999)
			rewindCalled := false
			handler := &deterministicTxErrorHandler{
				client:   client,
				getNonce: func(common.Address) uint64 { return 8 },
				metrics:  metrics,
			}
			noTransmission, err := handler.HandleError(
				ctx, lggr, tx, errors.New(errorText), store,
				func(from common.Address, nonce uint64) {
					rewindCalled = true
					reusedAddress = from
					reusedNonce = nonce
				},
			)
			require.NoError(t, err)
			require.True(t, noTransmission)
			require.True(t, rewindCalled)
			require.Equal(t, address, reusedAddress)
			require.Equal(t, uint64(7), reusedNonce)
			require.Equal(t, 1, client.calls)
			require.Equal(t, 1, metrics.discardCalls)
			require.Equal(t, 1, metrics.lifecycleCalls)
			require.NotEmpty(t, logs.All())
			var messageIDs any
			for _, field := range logs.All()[0].Context {
				if field.Key == "messageIDs" {
					messageIDs = field.Interface
				}
			}
			assert.Equal(t, "[0xbd285f7fba23af53bd57ef9df6b3124420db800a69590c9fd97fb4cf2d34e1a3]", fmt.Sprint(messageIDs))

			_, count, err := store.FetchUnconfirmedTransactionAtNonceWithCount(ctx, 7, address)
			require.NoError(t, err)
			require.Zero(t, count)
			next, err := store.UpdateUnstartedTransactionWithNonce(ctx, address, 7)
			require.NoError(t, err)
			require.NotNil(t, next, "the next message must reuse the rejected transaction's nonce")
		})
	}
}

func TestDeterministicTxErrorHandlerPurgesOlderNonceInsteadOfRewinding(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	address := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	store := storage.NewInMemoryStoreManager(logger.Test(t), big.NewInt(11155111))
	require.NoError(t, store.Add(address))
	for range 2 {
		_, err := store.CreateTransaction(ctx, &types.TxRequest{FromAddress: address, ToAddress: address, Value: big.NewInt(0)})
		require.NoError(t, err)
	}
	tx, err := store.UpdateUnstartedTransactionWithNonce(ctx, address, 7)
	require.NoError(t, err)
	_, err = store.UpdateUnstartedTransactionWithNonce(ctx, address, 8)
	require.NoError(t, err)
	tx.AttemptCount = 1

	metrics := &recordingDiscardMetrics{}
	handler := &deterministicTxErrorHandler{
		client:   &fixedPendingNonceClient{nonce: 7},
		getNonce: func(common.Address) uint64 { return 9 },
		metrics:  metrics,
	}
	noTransmission, err := handler.HandleError(ctx, logger.Test(t), tx, errors.New("intrinsic gas too low"), store,
		func(common.Address, uint64) { t.Fatal("an older nonce must not be rewound") })
	require.NoError(t, err)
	require.True(t, noTransmission)
	require.Equal(t, 1, metrics.discardCalls)
	require.Equal(t, 1, metrics.lifecycleCalls)

	purged, count, err := store.FetchUnconfirmedTransactionAtNonceWithCount(ctx, 7, address)
	require.NoError(t, err)
	require.Equal(t, 2, count)
	require.NotNil(t, purged)
	require.True(t, purged.IsPurgeable)
	later, _, err := store.FetchUnconfirmedTransactionAtNonceWithCount(ctx, 8, address)
	require.NoError(t, err)
	require.NotNil(t, later)
	require.False(t, later.IsPurgeable)
}

func TestDeterministicTxErrorHandlerLeavesAcceptedTransmissionAlone(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	address := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	store := storage.NewInMemoryStoreManager(logger.Test(t), big.NewInt(11155111))
	require.NoError(t, store.Add(address))
	_, err := store.CreateTransaction(ctx, &types.TxRequest{FromAddress: address, ToAddress: address, Value: big.NewInt(0)})
	require.NoError(t, err)
	tx, err := store.UpdateUnstartedTransactionWithNonce(ctx, address, 7)
	require.NoError(t, err)
	tx.AttemptCount = 1

	metrics := &recordingDiscardMetrics{}
	handler := &deterministicTxErrorHandler{
		client:   &fixedPendingNonceClient{nonce: 8},
		getNonce: func(common.Address) uint64 { return 8 },
		metrics:  metrics,
	}
	noTransmission, err := handler.HandleError(ctx, logger.Test(t), tx, errors.New("intrinsic gas too low"), store,
		func(common.Address, uint64) { t.Fatal("an accepted transmission must not rewind its nonce") })
	require.NoError(t, err)
	require.False(t, noTransmission)
	require.Zero(t, metrics.discardCalls)
	require.Zero(t, metrics.lifecycleCalls)
	remaining, _, err := store.FetchUnconfirmedTransactionAtNonceWithCount(ctx, 7, address)
	require.NoError(t, err)
	require.NotNil(t, remaining)
	require.False(t, remaining.IsPurgeable)
}

func TestDeterministicTxErrorHandlerReturnsPendingNonceFailure(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	address := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	store := storage.NewInMemoryStoreManager(logger.Test(t), big.NewInt(11155111))
	require.NoError(t, store.Add(address))
	_, err := store.CreateTransaction(ctx, &types.TxRequest{FromAddress: address, ToAddress: address, Value: big.NewInt(0)})
	require.NoError(t, err)
	tx, err := store.UpdateUnstartedTransactionWithNonce(ctx, address, 7)
	require.NoError(t, err)
	tx.AttemptCount = 1

	handler := &deterministicTxErrorHandler{
		client:   &fixedPendingNonceClient{err: errors.New("RPC unavailable")},
		getNonce: func(common.Address) uint64 { return 8 },
	}
	noTransmission, err := handler.HandleError(ctx, logger.Test(t), tx, errors.New("intrinsic gas too low"), store,
		func(common.Address, uint64) { t.Fatal("nonce must not change when its chain state is unknown") })
	require.ErrorContains(t, err, "RPC unavailable")
	require.False(t, noTransmission)
	remaining, _, err := store.FetchUnconfirmedTransactionAtNonceWithCount(ctx, 7, address)
	require.NoError(t, err)
	require.NotNil(t, remaining)
}

func TestDeterministicTxErrorHandlerDoesNotDiscardOtherTransactions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		attemptCount uint16
		err          error
		purgeable    bool
		nilNonce     bool
	}{
		{name: "later attempt", attemptCount: 2, err: errors.New("intrinsic gas too low")},
		{name: "purge transaction", attemptCount: 1, err: errors.New("intrinsic gas too low"), purgeable: true},
		{name: "unrelated error", attemptCount: 1, err: errors.New("replacement transaction underpriced")},
		{name: "nil error", attemptCount: 1, err: nil},
		{name: "nil nonce", attemptCount: 1, err: errors.New("intrinsic gas too low"), nilNonce: true},
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
			tx, err := store.UpdateUnstartedTransactionWithNonce(ctx, address, 7)
			require.NoError(t, err)
			tx.AttemptCount = tt.attemptCount
			tx.IsPurgeable = tt.purgeable
			if tt.nilNonce {
				tx.Nonce = nil
			}

			metrics := &recordingDiscardMetrics{}
			client := &fixedPendingNonceClient{nonce: 7}
			handler := &deterministicTxErrorHandler{
				client:   client,
				getNonce: func(common.Address) uint64 { return 8 },
				metrics:  metrics,
			}
			noTransmission, err := handler.HandleError(ctx, logger.Test(t), tx, tt.err, store,
				func(common.Address, uint64) { t.Fatal("nonce must not be rewound") })
			require.NoError(t, err)
			require.False(t, noTransmission)
			require.Zero(t, client.calls)
			require.Zero(t, metrics.discardCalls)
			require.Zero(t, metrics.lifecycleCalls)
			_, count, err := store.FetchUnconfirmedTransactionAtNonceWithCount(ctx, 7, address)
			require.NoError(t, err)
			require.Equal(t, 1, count)
		})
	}
}

type rejectingTxmClient struct {
	pendingNonce uint64
	sentNonces   []uint64
}

func (c *rejectingTxmClient) PendingNonceAt(context.Context, common.Address) (uint64, error) {
	return c.pendingNonce, nil
}

func (c *rejectingTxmClient) NonceAt(context.Context, common.Address, *big.Int) (uint64, error) {
	return c.pendingNonce, nil
}

func (c *rejectingTxmClient) SendTransaction(_ context.Context, tx *types.Transaction, _ *types.Attempt) error {
	c.sentNonces = append(c.sentNonces, *tx.Nonce)
	return errors.New("RPC call failed: intrinsic gas too low")
}

type staticAttemptBuilder struct{}

func (staticAttemptBuilder) NewAgnosticBumpAttempt(_ context.Context, _ logger.Logger, tx *types.Transaction, _ bool) (*types.Attempt, error) {
	return &types.Attempt{TxID: tx.ID, GasLimit: tx.SpecifiedGasLimit}, nil
}

func TestDeterministicTxErrorHandlerReusesNonceInRealTXM(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	address := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	chainID := big.NewInt(11155111)
	store := storage.NewInMemoryStoreManager(logger.Test(t), chainID)
	require.NoError(t, store.Add(address))
	client := &rejectingTxmClient{pendingNonce: 7}
	metrics := &recordingDiscardMetrics{}
	handler := &deterministicTxErrorHandler{client: client, metrics: metrics}
	manager := txm.NewTxm(logger.Test(t), chainID, client, staticAttemptBuilder{}, store, nil, txm.Config{},
		keystest.Addresses{address}, handler, txm.NewNoopTxmMetrics())
	handler.getNonce = manager.GetNonce
	for range 2 {
		_, err := manager.CreateTransaction(ctx, &types.TxRequest{FromAddress: address, ToAddress: address, Value: big.NewInt(0), SpecifiedGasLimit: 100_000})
		require.NoError(t, err)
	}
	manager.SetNonce(address, 7)

	shouldBackoff, err := manager.BroadcastTransaction(ctx, address)
	require.NoError(t, err)
	require.False(t, shouldBackoff)
	require.Equal(t, []uint64{7, 7}, client.sentNonces, "the next transaction must reuse the rejected nonce")
	require.Equal(t, uint64(7), manager.GetNonce(address))
	require.Equal(t, 2, metrics.discardCalls)
	require.Equal(t, 2, metrics.lifecycleCalls)
	_, count, err := store.FetchUnconfirmedTransactionAtNonceWithCount(ctx, 7, address)
	require.NoError(t, err)
	require.Zero(t, count)
}
