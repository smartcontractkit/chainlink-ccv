package evm

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-evm/pkg/assets"
	clevmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
	"github.com/smartcontractkit/chainlink-evm/pkg/gas"
	"github.com/smartcontractkit/chainlink-framework/chains/fees"
)

// purgeFeeBumps is one more bump than TXM v2 applies to any attempt, so a purge outbids anything
// the previous process could have sent for that nonce at the same market price.
const purgeFeeBumps = 6

// purgeFeeEstimator gives estimators without a max fee one. TXM v2 prices purge and nonce-gap
// attempts with GetMaxFee only, so on those estimators a stuck nonce otherwise wedges the key.
type purgeFeeEstimator struct {
	gas.EvmFeeEstimator
	bumpPercent uint16
	bumpMin     *assets.Wei
}

// withPurgeFeeFallback wraps estimator when its mode has no max fee: FeeHistory in legacy mode,
// and SuggestedPrice in either mode. Every other estimator is returned unchanged.
func withPurgeFeeFallback(estimator gas.EvmFeeEstimator, cfg clevmconfig.GasEstimator) gas.EvmFeeEstimator {
	if !estimatorLacksMaxFee(cfg.Mode(), cfg.EIP1559DynamicFees()) {
		return estimator
	}
	return &purgeFeeEstimator{EvmFeeEstimator: estimator, bumpPercent: cfg.BumpPercent(), bumpMin: cfg.BumpMin()}
}

func estimatorLacksMaxFee(mode string, eip1559 bool) bool {
	switch mode {
	case "FeeHistory":
		return !eip1559
	case "SuggestedPrice", "L2Suggested":
		return true
	default:
		return false
	}
}

// GetMaxFee prefers the estimator's own max fee and otherwise bumps the current legacy price
// purgeFeeBumps times with v1's bump rule, capped at maxFeePrice.
func (e *purgeFeeEstimator) GetMaxFee(
	ctx context.Context, calldata []byte, feeLimit uint64, maxFeePrice *assets.Wei,
	fromAddress, toAddress *common.Address, opts ...fees.Opt,
) (gas.EvmFee, uint64, error) {
	fee, limit, err := e.EvmFeeEstimator.GetMaxFee(ctx, calldata, feeLimit, maxFeePrice, fromAddress, toAddress, opts...)
	if err == nil {
		return fee, limit, nil
	}
	fee, limit, err = e.GetFee(ctx, calldata, feeLimit, maxFeePrice, fromAddress, toAddress, opts...)
	if err != nil || fee.GasPrice == nil {
		return fee, limit, err
	}
	price := fee.GasPrice.ToInt()
	bumpMin := big.NewInt(0)
	if e.bumpMin != nil {
		bumpMin = e.bumpMin.ToInt()
	}
	for range purgeFeeBumps {
		price = fees.MaxBumpedFee(price, e.bumpPercent, bumpMin)
	}
	if maxFeePrice != nil && price.Cmp(maxFeePrice.ToInt()) > 0 {
		price = new(big.Int).Set(maxFeePrice.ToInt())
	}
	fee.GasPrice = assets.NewWei(price)
	return fee, limit, nil
}
