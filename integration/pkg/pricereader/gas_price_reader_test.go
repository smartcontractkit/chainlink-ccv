package pricereader_test

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/pricereader"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/pricereader/pricereadertest"
	"github.com/smartcontractkit/chainlink-evm/pkg/assets"
)

type fakeGasClient struct {
	price *big.Int
	err   error
}

func (f fakeGasClient) SuggestGasPrice(context.Context) (*big.Int, error) { return f.price, f.err }

type fakeDAOracle struct {
	price *assets.Wei
	err   error
}

func (f fakeDAOracle) GasPrice(context.Context) (*assets.Wei, error) { return f.price, f.err }

func provide(oracle pricereader.DAGasPriceOracle) pricereader.DAGasPriceOracleProvider {
	return func(context.Context) (pricereader.DAGasPriceOracle, error) { return oracle, nil }
}

func TestGetGasPriceScalesToWholeNativeTokenPrecision(t *testing.T) {
	gwei := big.NewInt(1e9)
	tests := []struct {
		name     string
		decimals uint8
		scale    *big.Int
	}{
		{name: "18 decimals", decimals: 18, scale: big.NewInt(1e18)},
		{name: "8 decimals", decimals: 8, scale: new(big.Int).Exp(big.NewInt(10), big.NewInt(28), nil)},
		{name: "36 decimals", decimals: 36, scale: big.NewInt(1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := pricereader.NewEVMGasPriceReader(
				fakeGasClient{price: gwei},
				provide(fakeDAOracle{price: assets.NewWei(big.NewInt(3e9))}),
				tt.decimals,
			)
			require.NoError(t, err)

			price, err := reader.GetGasPrice(context.Background())
			require.NoError(t, err)
			require.Equal(t, new(big.Int).Mul(gwei, tt.scale), price.ExecutionFee.ToInt())
			require.Equal(t, new(big.Int).Mul(big.NewInt(3e9), tt.scale), price.DAFee.ToInt())
		})
	}
}

func TestGetGasPriceWithSimulatedChain(t *testing.T) {
	env := pricereadertest.New(t)
	da := big.NewInt(3e9)
	reader, err := pricereader.NewEVMGasPriceReader(env.Client, provide(fakeDAOracle{price: assets.NewWei(da)}), 18)
	require.NoError(t, err)

	want, err := env.Client.SuggestGasPrice(context.Background())
	require.NoError(t, err)
	price, err := reader.GetGasPrice(context.Background())
	require.NoError(t, err)
	require.Equal(t, new(big.Int).Mul(want, big.NewInt(1e18)), price.ExecutionFee.ToInt())
	require.Equal(t, new(big.Int).Mul(da, big.NewInt(1e18)), price.DAFee.ToInt())
}

func TestGetGasPriceWithoutDAOracleHasZeroDAFee(t *testing.T) {
	reader, err := pricereader.NewEVMGasPriceReader(fakeGasClient{price: big.NewInt(5)}, nil, 18)
	require.NoError(t, err)

	price, err := reader.GetGasPrice(context.Background())
	require.NoError(t, err)
	require.Equal(t, big.NewInt(5e18), price.ExecutionFee.ToInt())
	require.Zero(t, price.DAFee.ToInt().Sign())
}

func TestGetGasPriceReturnsErrors(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name   string
		client fakeGasClient
		oracle pricereader.DAGasPriceOracleProvider
		want   string
	}{
		{name: "client error", client: fakeGasClient{err: boom}, want: "execution gas price"},
		{name: "oracle error", client: fakeGasClient{price: big.NewInt(1)}, oracle: provide(fakeDAOracle{err: boom}), want: "read the data availability gas price"},
		{
			name:   "oracle start error",
			client: fakeGasClient{price: big.NewInt(1)},
			oracle: func(context.Context) (pricereader.DAGasPriceOracle, error) { return nil, boom },
			want:   "start the data availability gas price oracle",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := pricereader.NewEVMGasPriceReader(tt.client, tt.oracle, 18)
			require.NoError(t, err)

			_, err = reader.GetGasPrice(context.Background())
			require.ErrorIs(t, err, boom)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestNewEVMGasPriceReaderRejectsInvalidArguments(t *testing.T) {
	_, err := pricereader.NewEVMGasPriceReader(nil, nil, 18)
	require.ErrorContains(t, err, "client is nil")

	_, err = pricereader.NewEVMGasPriceReader(fakeGasClient{}, nil, 37)
	require.ErrorContains(t, err, "decimals")
}

func TestGetGasPriceStartsDAOracleOnFirstUseAndCachesIt(t *testing.T) {
	calls := 0
	reader, err := pricereader.NewEVMGasPriceReader(fakeGasClient{price: big.NewInt(1)}, func(context.Context) (pricereader.DAGasPriceOracle, error) {
		calls++
		return fakeDAOracle{price: assets.NewWei(big.NewInt(2))}, nil
	}, 18)
	require.NoError(t, err)
	require.Zero(t, calls, "the constructor must not start the oracle")

	for range 2 {
		_, err = reader.GetGasPrice(context.Background())
		require.NoError(t, err)
	}
	require.Equal(t, 1, calls)
}

func TestGetGasPriceRetriesTheDAOracleAfterAFailure(t *testing.T) {
	calls := 0
	reader, err := pricereader.NewEVMGasPriceReader(fakeGasClient{price: big.NewInt(1)}, func(context.Context) (pricereader.DAGasPriceOracle, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("not ready")
		}
		return fakeDAOracle{price: assets.NewWei(big.NewInt(2))}, nil
	}, 18)
	require.NoError(t, err)

	_, err = reader.GetGasPrice(context.Background())
	require.ErrorContains(t, err, "not ready")
	price, err := reader.GetGasPrice(context.Background())
	require.NoError(t, err)
	require.Equal(t, big.NewInt(2e18), price.DAFee.ToInt())
}

func TestGetGasPriceWithNilOracleFromProviderHasZeroDAFee(t *testing.T) {
	reader, err := pricereader.NewEVMGasPriceReader(fakeGasClient{price: big.NewInt(1)}, provide(nil), 18)
	require.NoError(t, err)

	price, err := reader.GetGasPrice(context.Background())
	require.NoError(t, err)
	require.Zero(t, price.DAFee.ToInt().Sign())
}
