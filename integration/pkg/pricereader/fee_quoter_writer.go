package pricereader

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ chainaccess.FeeQuoterWriter = (*LoggingFeeQuoterWriter)(nil)

// LoggingFeeQuoterWriter logs the price updates and does not send a transaction.
// It is a stub until the writer sends the updates to the Fee Quoter.
type LoggingFeeQuoterWriter struct {
	lggr    logger.Logger
	address common.Address
}

// NewLoggingFeeQuoterWriter creates a writer that only logs.
func NewLoggingFeeQuoterWriter(lggr logger.Logger, address common.Address) *LoggingFeeQuoterWriter {
	return &LoggingFeeQuoterWriter{lggr: lggr, address: address}
}

// UpdatePrices logs the updates and returns nil.
func (w *LoggingFeeQuoterWriter) UpdatePrices(_ context.Context, tokenPrices []protocol.FeeTokenPriceUpdate, gasPrices []protocol.GasTokenPriceUpdate) error {
	tokens := make([]map[string]string, 0, len(tokenPrices))
	for _, update := range tokenPrices {
		tokens = append(tokens, map[string]string{
			"address":          update.Address.String(),
			"usdPerWholeToken": bigString((*big.Int)(update.Price)),
		})
	}
	gas := make([]map[string]any, 0, len(gasPrices))
	for _, update := range gasPrices {
		gas = append(gas, map[string]any{
			"chainSelector":   update.ChainSelector,
			"executionFeeUSD": bigString((*big.Int)(update.USDGasPrice.ExecutionFee)),
			"daFeeUSD":        bigString((*big.Int)(update.USDGasPrice.DAFee)),
		})
	}
	w.lggr.Infow("Fee quoter price update not sent, the writer only logs",
		"feeQuoter", w.address.Hex(),
		"tokenPrices", tokens,
		"gasPrices", gas,
	)
	return nil
}

func bigString(v *big.Int) string {
	if v == nil {
		return "<nil>"
	}
	return v.String()
}
