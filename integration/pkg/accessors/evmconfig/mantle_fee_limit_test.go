package evmconfig

import (
	"context"
	"math/big"
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/assets"
	"github.com/smartcontractkit/chainlink-evm/pkg/gas"
	gasmocks "github.com/smartcontractkit/chainlink-evm/pkg/gas/mocks"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

type mantleLimitEstimationConfig struct {
	multiplier float32
}

func (c mantleLimitEstimationConfig) LimitMultiplier() float32 { return c.multiplier }
func (mantleLimitEstimationConfig) EstimateLimit() bool        { return false }
func (mantleLimitEstimationConfig) SenderAddress() *evmtypes.EIP55Address {
	return nil
}

func estimatedLimitWithMultiplier(t *testing.T, multiplier decimal.Decimal, feeLimit uint64) uint64 {
	t.Helper()
	underlying := gasmocks.NewEvmEstimator(t)
	underlying.EXPECT().GetDynamicFee(mock.Anything, mock.Anything).Return(gas.DynamicFee{
		GasFeeCap: assets.NewWei(big.NewInt(100)),
		GasTipCap: assets.NewWei(big.NewInt(1)),
	}, nil).Once()
	estimator := gas.NewEvmFeeEstimator(logger.Test(t), underlying, true, mantleLimitEstimationConfig{
		multiplier: float32(multiplier.InexactFloat64()),
	}, nil)
	_, estimatedLimit, err := estimator.GetFee(context.Background(), nil, feeLimit, assets.NewWei(big.NewInt(1000)), nil, nil)
	require.NoError(t, err)
	return estimatedLimit
}

func TestMantleConversionAndExplicitFeeLimit(t *testing.T) {
	built, conversion := buildConverted(t, `
[[EVM]]
ChainID = '5000'
[EVM.GasEstimator]
LimitMultiplier = '23000'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://mantle.example.com'
`)
	require.Equal(t, "1", built.GasEstimator.LimitMultiplier.String())
	require.Contains(t, conversion.Warnings, "chain 5000: standalone overrides GasEstimator.LimitMultiplier = 23000 with gas_estimator_limit_multiplier = 1; TXM v2 otherwise multiplies explicit CCIP fee limits by the legacy value")

	infos, err := conversion.Config.ToInfos()
	require.NoError(t, err)
	for _, info := range infos {
		require.NotNil(t, info.GasEstimatorLimitMultiplier)
		require.Equal(t, "1", info.GasEstimatorLimitMultiplier.String())
	}

	const explicitFeeLimit = uint64(694835)
	estimated := estimatedLimitWithMultiplier(t, *built.GasEstimator.LimitMultiplier, explicitFeeLimit)
	require.Equal(t, explicitFeeLimit, estimated)
	require.NotEqual(t, uint64(15981205000), estimated)
}

func TestMantleStandaloneRejectsUnsafeLimitMultiplier(t *testing.T) {
	unsafe := decimal.NewFromInt(23000)
	_, err := BuildChainlinkEVMTOML(Info{
		ChainID:                     "5000",
		GasEstimatorLimitMultiplier: &unsafe,
		Nodes:                       []Node{{Name: "primary", HTTPUrl: "https://mantle.example.com"}},
	})
	require.ErrorContains(t, err, "chain 5000 (Mantle)")
	require.ErrorContains(t, err, "LimitMultiplier = 23000")
	require.ErrorContains(t, err, "gas_estimator_limit_multiplier = 1")
}

func TestNonMantleAndZeroFeeLimitBehaviorUnchanged(t *testing.T) {
	built, _ := buildConverted(t, `
[[EVM]]
ChainID = '11155111'
[EVM.GasEstimator]
LimitMultiplier = '4'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`)
	require.Equal(t, "4", built.GasEstimator.LimitMultiplier.String())
	require.Equal(t, uint64(400), estimatedLimitWithMultiplier(t, *built.GasEstimator.LimitMultiplier, 100))
	require.Zero(t, estimatedLimitWithMultiplier(t, *built.GasEstimator.LimitMultiplier, 0))
}
