// Package pricereader reads gas prices and Fee Quoter state from an EVM chain.
package pricereader

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/sync/errgroup"

	"github.com/smartcontractkit/chainlink-ccv/common/lazy"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-evm/pkg/assets"
)

// MaxNativeTokenDecimals is the largest number of native token decimals that the reader accepts.
// The price has 1e36 precision (protocol.WholeNativeTokenPerGasUnit), so 10^(36-decimals) must be a whole number.
const MaxNativeTokenDecimals = 36

var _ chainaccess.GasPriceReader = (*EVMGasPriceReader)(nil)

type gasPriceClient interface {
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
}

// DAGasPriceOracle returns the data availability (L1) gas price of a rollup chain.
// The rollups.L1Oracle type of chainlink-evm satisfies this interface.
type DAGasPriceOracle interface {
	// GasPrice returns the data availability gas price in wei.
	GasPrice(ctx context.Context) (*assets.Wei, error)
}

// DAGasPriceOracleProvider returns the oracle on the first use. It returns a nil oracle when the chain has no DA fee.
type DAGasPriceOracleProvider func(ctx context.Context) (DAGasPriceOracle, error)

// EVMGasPriceReader reads the execution gas price and the data availability gas price of an EVM chain.
type EVMGasPriceReader struct {
	client         gasPriceClient
	daOracle       *lazy.Lazy[DAGasPriceOracle]
	nativeDecimals uint8
}

// NewEVMGasPriceReader creates a gas price reader. It does not call the chain.
// The provider can be nil. A nil provider or a nil oracle means that the chain has no data availability fee.
// The nativeDecimals argument is the decimals of the unit of the RPC gas price. It is 18 for most chains.
func NewEVMGasPriceReader(client gasPriceClient, daOracle DAGasPriceOracleProvider, nativeDecimals uint8) (*EVMGasPriceReader, error) {
	if client == nil {
		return nil, errors.New("gas price client is nil")
	}
	if nativeDecimals > MaxNativeTokenDecimals {
		return nil, fmt.Errorf("native token decimals %d is more than %d", nativeDecimals, MaxNativeTokenDecimals)
	}
	reader := &EVMGasPriceReader{client: client, nativeDecimals: nativeDecimals}
	if daOracle != nil {
		reader.daOracle = lazy.New(daOracle)
	}
	return reader, nil
}

// GetGasPrice returns the gas price in whole native tokens per gas unit, with 1e36 precision.
// The execution fee and the data availability fee are read in parallel.
func (r *EVMGasPriceReader) GetGasPrice(ctx context.Context) (protocol.NativeGasPrice, error) {
	var executionWei, daWei *big.Int

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		price, err := r.client.SuggestGasPrice(gctx)
		if err != nil {
			return fmt.Errorf("failed to read the execution gas price: %w", err)
		}
		executionWei = price
		return nil
	})
	if r.daOracle != nil {
		g.Go(func() error {
			oracle, err := r.daOracle.Value(gctx)
			if err != nil {
				return fmt.Errorf("failed to start the data availability gas price oracle: %w", err)
			}
			if oracle == nil {
				return nil
			}
			price, err := oracle.GasPrice(gctx)
			if err != nil {
				return fmt.Errorf("failed to read the data availability gas price: %w", err)
			}
			if price != nil {
				daWei = price.ToInt()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return protocol.NativeGasPrice{}, err
	}

	scale := pow10(MaxNativeTokenDecimals - uint(r.nativeDecimals))
	return protocol.NativeGasPrice{
		ExecutionFee: scaleNativePrice(executionWei, scale),
		DAFee:        scaleNativePrice(daWei, scale),
	}, nil
}

// scaleNativePrice multiplies a price in the smallest native unit by scale.
// A nil price gives a zero price.
func scaleNativePrice(price, scale *big.Int) *protocol.WholeNativeTokenPerGasUnit {
	if price == nil {
		return new(protocol.WholeNativeTokenPerGasUnit)
	}
	return (*protocol.WholeNativeTokenPerGasUnit)(new(big.Int).Mul(price, scale))
}

func pow10(n uint) *big.Int {
	return new(big.Int).Exp(big.NewInt(10), new(big.Int).SetUint64(uint64(n)), nil)
}
