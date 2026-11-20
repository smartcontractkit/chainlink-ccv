package evm

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/assets"
	"github.com/smartcontractkit/chainlink-evm/pkg/gas"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm"
	txmtypes "github.com/smartcontractkit/chainlink-evm/pkg/txm/types"
	"github.com/smartcontractkit/chainlink-framework/chains/fees"
)

// fakeFeeEstimator answers only the two fee calls the purge fallback makes.
type fakeFeeEstimator struct {
	gas.EvmFeeEstimator
	maxFee gas.EvmFee
	maxErr error
	fee    gas.EvmFee
	feeErr error
	limit  uint64
}

func (f *fakeFeeEstimator) GetMaxFee(context.Context, []byte, uint64, *assets.Wei, *common.Address, *common.Address, ...fees.Opt) (gas.EvmFee, uint64, error) {
	return f.maxFee, f.limit, f.maxErr
}

func (f *fakeFeeEstimator) GetFee(context.Context, []byte, uint64, *assets.Wei, *common.Address, *common.Address, ...fees.Opt) (gas.EvmFee, uint64, error) {
	return f.fee, f.limit, f.feeErr
}

func purgeFee(t *testing.T, inner *fakeFeeEstimator, maxFeePrice *assets.Wei) (gas.EvmFee, uint64, error) {
	t.Helper()
	subject := &purgeFeeEstimator{EvmFeeEstimator: inner, bumpPercent: 20, bumpMin: assets.GWei(1)}
	return subject.GetMaxFee(t.Context(), nil, 21_000, maxFeePrice, nil, nil)
}

func TestEstimatorLacksMaxFee(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode    string
		eip1559 bool
		want    bool
	}{
		{mode: "FeeHistory", eip1559: false, want: true},
		{mode: "FeeHistory", eip1559: true, want: false},
		{mode: "SuggestedPrice", eip1559: false, want: true},
		{mode: "SuggestedPrice", eip1559: true, want: true},
		{mode: "L2Suggested", eip1559: false, want: true},
		{mode: "BlockHistory", eip1559: false, want: false},
		{mode: "BlockHistory", eip1559: true, want: false},
		{mode: "FixedPrice", eip1559: false, want: false},
		{mode: "Arbitrum", eip1559: false, want: false},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, estimatorLacksMaxFee(tt.mode, tt.eip1559), "mode %s, eip1559 %v", tt.mode, tt.eip1559)
	}
}

// Monad testnet ships FeeHistory in legacy mode, one of the chains where purges could not be priced.
func TestWithPurgeFeeFallbackWrapsOnlyEstimatorsWithoutAMaxFee(t *testing.T) {
	t.Parallel()

	nodes := []Node{{HTTPUrl: "http://node.internal:8545"}}
	monad, err := newChainlinkEVMConfig(Info{ChainID: "10143", Nodes: nodes})
	require.NoError(t, err)
	require.Equal(t, "FeeHistory", monad.EVM().GasEstimator().Mode(), "the premise: Monad testnet uses FeeHistory")
	require.False(t, monad.EVM().GasEstimator().EIP1559DynamicFees(), "the premise: in legacy mode")
	inner := &fakeFeeEstimator{}
	require.IsType(t, &purgeFeeEstimator{}, withPurgeFeeFallback(inner, monad.EVM().GasEstimator()))

	sepolia, err := newChainlinkEVMConfig(Info{ChainID: "11155111", Nodes: nodes})
	require.NoError(t, err)
	require.Same(t, inner, withPurgeFeeFallback(inner, sepolia.EVM().GasEstimator()),
		"an estimator with its own max fee is left alone")
}

func TestPurgeFeeOutbidsAnythingTheLastProcessCouldHaveSent(t *testing.T) {
	t.Parallel()

	market := assets.GWei(10)
	inner := &fakeFeeEstimator{
		maxErr: errors.New("max legacy gas is not supported for FeeHistoryEstimator"),
		fee:    gas.EvmFee{GasPrice: market},
		limit:  25_000,
	}
	fee, limit, err := purgeFee(t, inner, assets.GWei(1_000))
	require.NoError(t, err)
	require.Equal(t, uint64(25_000), limit, "the estimator's gas limit is kept")
	require.Equal(t, big.NewInt(29_859_840_000), fee.GasPrice.ToInt(), "10 gwei bumped by 20% six times")

	// TXM v2 bumps an attempt at most five times; a replacement must beat that by geth's 10%.
	highestPrior := market.ToInt()
	for range purgeFeeBumps - 1 {
		highestPrior = fees.AddPercentage(highestPrior, 20)
	}
	require.Positive(t, fee.GasPrice.ToInt().Cmp(fees.AddPercentage(highestPrior, 10)))
}

func TestPurgeFeeIsCappedAtTheKeysMaxPrice(t *testing.T) {
	t.Parallel()

	inner := &fakeFeeEstimator{maxErr: errors.New("unsupported"), fee: gas.EvmFee{GasPrice: assets.GWei(10)}, limit: 21_000}
	fee, _, err := purgeFee(t, inner, assets.GWei(15))
	require.NoError(t, err)
	require.Equal(t, assets.GWei(15).ToInt(), fee.GasPrice.ToInt())
}

func TestPurgeFeePrefersTheEstimatorsOwnMaxFee(t *testing.T) {
	t.Parallel()

	inner := &fakeFeeEstimator{maxFee: gas.EvmFee{GasPrice: assets.GWei(50)}, fee: gas.EvmFee{GasPrice: assets.GWei(10)}, limit: 21_000}
	fee, _, err := purgeFee(t, inner, assets.GWei(1_000))
	require.NoError(t, err)
	require.Equal(t, assets.GWei(50).ToInt(), fee.GasPrice.ToInt())
}

// End to end through TXM v2's attempt builder: the gap-fill transaction it creates for a nonce gap
// fails to price on a FeeHistory legacy chain without the fallback, and builds with it.
func TestPurgeAttemptBuildsOnAChainWhoseEstimatorHasNoMaxFee(t *testing.T) {
	t.Parallel()

	const privateKey = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	key, err := crypto.HexToECDSA(privateKey)
	require.NoError(t, err)
	from := crypto.PubkeyToAddress(key.PublicKey)
	keystore := txm.NewKeystore(big.NewInt(10143))
	require.NoError(t, keystore.Add(privateKey))

	cfg, err := newChainlinkEVMConfig(Info{ChainID: "10143", Nodes: []Node{{HTTPUrl: "http://node.internal:8545"}}})
	require.NoError(t, err)
	inner := &fakeFeeEstimator{
		maxErr: errors.New("max legacy gas is not supported for FeeHistoryEstimator"),
		fee:    gas.EvmFee{GasPrice: assets.GWei(10)},
		limit:  21_000,
	}
	priceMax := func(common.Address) *assets.Wei { return assets.GWei(1_000) }
	nonce := uint64(7)
	gapFill := &txmtypes.Transaction{ID: 1, Nonce: &nonce, FromAddress: from, Value: big.NewInt(0), IsPurgeable: true}
	lggr := logger.Test(t)

	_, err = txm.NewAttemptBuilder(priceMax, inner, keystore, 21_000, false).
		NewAgnosticBumpAttempt(t.Context(), lggr, gapFill, false)
	require.Error(t, err, "the premise: without the fallback the gap-fill attempt cannot be priced")

	attempt, err := txm.NewAttemptBuilder(priceMax, withPurgeFeeFallback(inner, cfg.EVM().GasEstimator()), keystore, 21_000, false).
		NewAgnosticBumpAttempt(t.Context(), lggr, gapFill, false)
	require.NoError(t, err)
	require.Positive(t, attempt.Fee.GasPrice.Cmp(assets.GWei(10)), "a purge is priced above the market")
	require.Equal(t, nonce, attempt.SignedTransaction.Nonce())
}

func TestPurgeFeeReturnsTheEstimatorsErrorWhenItCannotPriceAtAll(t *testing.T) {
	t.Parallel()

	feeErr := errors.New("rpc down")
	inner := &fakeFeeEstimator{maxErr: errors.New("unsupported"), feeErr: feeErr}
	_, _, err := purgeFee(t, inner, assets.GWei(1_000))
	require.ErrorIs(t, err, feeErr)
}
