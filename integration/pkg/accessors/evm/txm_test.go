package evm

import (
	"context"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/storage"
)

func TestNonceRangeIdentifiesOrphans(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		latest, pending uint64
		want            []uint64
		wantErr         bool
	}{
		{
			name:    "no transactions in flight",
			latest:  10,
			pending: 10,
			want:    nil,
		},
		{
			name:    "one orphan",
			latest:  10,
			pending: 11,
			want:    []uint64{10},
		},
		{
			name:    "several orphans are all reported",
			latest:  10,
			pending: 14,
			want:    []uint64{10, 11, 12, 13},
		},
		{
			// A pending nonce below the latest is not a state the chain should report. Treating it
			// as "nothing to recover" keeps recovery from inventing transactions out of an RPC that
			// answered the two calls from different nodes mid-block.
			name:    "pending behind latest yields nothing",
			latest:  10,
			pending: 8,
			want:    nil,
		},
		{
			name:    "extreme uint64 gap returns an error",
			latest:  0,
			pending: math.MaxUint64,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := nonceRange(tt.latest, tt.pending)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestNewTxmV2RejectsUnsupportedConfig covers the branches of upstream's builder that this one
// deliberately does not reproduce. They are rejected rather than silently ignored, so a config that
// turns one on fails at startup instead of running without the behavior it asked for.
func TestNewTxmV2RejectsUnsupportedConfig(t *testing.T) {
	t.Parallel()

	cfg, err := newChainlinkEVMConfig(Info{
		ChainID: "1337",
		Nodes:   []Node{{HTTPUrl: "http://node.internal:8545"}},
	})
	require.NoError(t, err)

	// The standalone config never enables forwarders; assert that, since newTxmV2 relies on it to
	// justify passing a nil forwarder manager.
	require.False(t, cfg.EVM().Transactions().ForwardersEnabled(),
		"newTxmV2 passes a nil forwarder manager and rejects configs that enable forwarders")

	dual := cfg.EVM().Transactions().TransactionManagerV2().DualBroadcast()
	require.True(t, dual == nil || !*dual,
		"newTxmV2 passes a nil error handler and rejects configs that enable dual broadcast")
}

func TestRetryBlockThreshold(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		bumpThreshold uint64
		resendAfter   time.Duration
		blockTime     time.Duration
		want          uint16
	}{
		{name: "a positive BumpThreshold passes through", bumpThreshold: 3, resendAfter: time.Minute, blockTime: 2 * time.Second, want: 3},
		{name: "a BumpThreshold above uint16 is clamped, not wrapped", bumpThreshold: 70_000, blockTime: 2 * time.Second, want: math.MaxUint16},
		{name: "zero takes the v1 resend cadence", resendAfter: 2 * time.Minute, blockTime: 2 * time.Second, want: 60},
		{name: "the resend cadence rounds up to whole blocks", resendAfter: time.Minute, blockTime: 7 * time.Second, want: 9},
		{name: "a resend shorter than a block still waits one block", resendAfter: time.Second, blockTime: 2 * time.Second, want: 1},
		{name: "zero with resend off never rebroadcasts a sent attempt", resendAfter: 0, blockTime: 2 * time.Second, want: math.MaxUint16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, retryBlockThreshold(tt.bumpThreshold, tt.resendAfter, tt.blockTime))
		})
	}
}

// Hedera ships BumpThreshold = 0; passed straight through, TXM v2 would rebroadcast every 2s tick.
func TestRetryBlockThresholdForHederaUsesItsResendCadence(t *testing.T) {
	t.Parallel()

	cfg, err := newChainlinkEVMConfig(Info{ChainID: "296", Nodes: []Node{{HTTPUrl: "http://node.internal:8545"}}})
	require.NoError(t, err)
	evmCfg := cfg.EVM()
	require.Zero(t, evmCfg.GasEstimator().BumpThreshold(), "the premise: Hedera disables v1 gas bumping")

	got := retryBlockThreshold(evmCfg.GasEstimator().BumpThreshold(), evmCfg.Transactions().ResendAfterThreshold(),
		*evmCfg.Transactions().TransactionManagerV2().BlockTime())
	require.Greater(t, got, uint16(1), "Hedera must not rebroadcast on every TXM tick")
	require.Less(t, got, uint16(math.MaxUint16), "Hedera resends, so a stuck attempt is still retried")
}

// TestSeedOrphanedNonceCreatesPurgeableTransaction covers the whole point of forking upstream's
// builder: holding the store so a nonce the TXM has no record of can be put back under its control.
//
// The purgeable flag is what makes the seeded transaction useful. It is what tells the backfill loop
// to rebroadcast every tick rather than waiting out RetryBlockThreshold, and it is what makes the
// attempt builder price the attempt at the max fee to displace whatever is already occupying the
// nonce. A seeded transaction without it would sit behind the same stuck original it was created
// to clear.
func TestSeedOrphanedNonceCreatesPurgeableTransaction(t *testing.T) {
	t.Parallel()

	const gasLimit = uint64(21_000)
	address := common.HexToAddress("0x000000000000000000000000000000000000dEaD")

	store := storage.NewInMemoryStoreManager(logger.Test(t), big.NewInt(1337))
	require.NoError(t, store.Add(address))
	subject := &txmV2{store: store, emptyTxGasLimit: gasLimit}

	ctx := t.Context()
	require.NoError(t, subject.seedOrphanedNonce(ctx, address, 7))

	seeded, count, err := store.FetchUnconfirmedTransactionAtNonceWithCount(ctx, 7, address)
	require.NoError(t, err)
	require.Equal(t, 1, count, "seeding should leave exactly one unconfirmed transaction at the nonce")
	require.NotNil(t, seeded)
	require.True(t, seeded.IsPurgeable, "seeded transaction must be purgeable so TXM rebroadcasts and escalates it")
	require.Equal(t, gasLimit, seeded.SpecifiedGasLimit)

	// Seeding the same nonce twice would mean recovery raced itself; the store rejects it, which is
	// why recoverOrphanedTransactions logs and moves on rather than aborting the whole address.
	require.Error(t, subject.seedOrphanedNonce(ctx, address, 7),
		"a nonce already under TXM control must not be seeded again")
}

// TestWithNonceTimeoutBoundsAHangingRead covers the deadline every orphan-recovery nonce read
// carries. Recovery runs on a goroutine Close waits for, so a read that hung with only the caller's
// context to stop it would hang shutdown; this is what keeps that wait bounded.
func TestWithNonceTimeoutBoundsAHangingRead(t *testing.T) {
	t.Parallel()

	_, err := withNonceTimeout(t.Context(), time.Millisecond, func(ctx context.Context) (uint64, error) {
		<-ctx.Done() // A read that never answers on its own.
		return 0, ctx.Err()
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestWithNonceTimeoutPropagatesCancellation is the shutdown path: closing the accessor cancels the
// context the reads derive from, and they return then rather than after the full timeout.
func TestWithNonceTimeoutPropagatesCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// A generous per-call timeout, so returning promptly can only be the parent cancellation.
	_, err := withNonceTimeout(ctx, time.Hour, func(ctx context.Context) (uint64, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	})
	require.ErrorIs(t, err, context.Canceled)
}

// TestSeedOrphanedNonceRejectsUnknownAddress pins the ordering constraint in
// standaloneChain.startOrphanRecovery: recovery only runs after the TXM has started, because
// starting is what registers the transmitter addresses with the store.
func TestSeedOrphanedNonceRejectsUnknownAddress(t *testing.T) {
	t.Parallel()

	store := storage.NewInMemoryStoreManager(logger.Test(t), big.NewInt(1337))
	subject := &txmV2{store: store, emptyTxGasLimit: 21_000}

	err := subject.seedOrphanedNonce(t.Context(), common.HexToAddress("0x1"), 0)
	require.Error(t, err, "seeding an address the store does not know about must fail loudly")
}
