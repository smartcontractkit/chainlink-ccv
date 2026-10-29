package pricereader

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustBig(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 10)
	require.True(t, ok)
	return v
}

func TestOnChainTokenPriceToUSDPerWholeToken(t *testing.T) {
	tests := []struct {
		name     string
		price    string
		decimals uint8
		want     string
	}{
		{name: "18 decimals", price: "15000000000000000000", decimals: 18, want: "15000000000000000000"},
		{name: "6 decimals", price: "1000000000000000000000000000000", decimals: 6, want: "1000000000000000000"},
		{name: "8 decimals", price: "60000000000000000000000000000000", decimals: 8, want: "6000000000000000000000"},
		{name: "0 decimals", price: "1000000000000000000", decimals: 0, want: "1"},
		{name: "zero price", price: "0", decimals: 18, want: "0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := onChainTokenPriceToUSDPerWholeToken(mustBig(t, tt.price), tt.decimals)
			require.Equal(t, mustBig(t, tt.want), got.ToInt())
		})
	}
}

func TestUnpackGasPrice(t *testing.T) {
	maxPart := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 112), big.NewInt(1))
	tests := []struct {
		name          string
		da, execution *big.Int
	}{
		{name: "both set", da: big.NewInt(7), execution: big.NewInt(5)},
		{name: "only execution", da: big.NewInt(0), execution: big.NewInt(5)},
		{name: "only DA", da: big.NewInt(7), execution: big.NewInt(0)},
		{name: "both at the maximum", da: maxPart, execution: maxPart},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packed := new(big.Int).Or(new(big.Int).Lsh(tt.da, packedGasPriceBits), tt.execution)
			got := unpackGasPrice(packed)
			require.Equal(t, tt.execution.String(), got.ExecutionFee.ToInt().String())
			require.Equal(t, tt.da.String(), got.DAFee.ToInt().String())
		})
	}
}

func TestScaleNativePriceNilIsZero(t *testing.T) {
	require.Zero(t, scaleNativePrice(nil, big.NewInt(10)).ToInt().Sign())
}
