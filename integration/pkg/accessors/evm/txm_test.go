package evm

import (
	"math/big"
	"testing"

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, nonceRange(tt.latest, tt.pending))
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

// TestSeedOrphanedNonceCreatesPurgeableTransaction covers the whole point of forking upstream's
// builder: holding the store so a nonce the TXM has no record of can be put back under its control.
//
// The purgeable flag is what makes the seeded transaction useful. It is what tells the backfill loop
// to rebroadcast every tick with an escalating fee rather than waiting out RetryBlockThreshold, and
// it is what makes the attempt builder price the attempt to displace whatever is already occupying
// the nonce. A seeded transaction without it would sit behind the same stuck original it was
// created to clear.
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
