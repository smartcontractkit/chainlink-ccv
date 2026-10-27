package pricereader

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/fee_quoter"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/erc20"
)

// weibarPerTinybar is the divisor applied to Hedera gas prices.
// Hedera gas price RPC call returns 1e18 yet the atomic unit
// for the actual token is 1e8. Gas prices need to be scaled down
// by this factor
var weibarPerTinybar = big.NewInt(1e10)

var _ chainaccess.FeeQuoterWriter = (*LoggingFeeQuoterWriter)(nil)

// LoggingFeeQuoterWriter logs the price updates and does not send a transaction.
// It is a stub until the writer sends the updates to the Fee Quoter.
type LoggingFeeQuoterWriter struct {
	lggr    logger.Logger
	client  batchClient
	address common.Address

	mu       sync.Mutex
	decimals map[common.Address]uint8
}

// NewLoggingFeeQuoterWriter creates a writer that only logs. It does not call the chain.
func NewLoggingFeeQuoterWriter(lggr logger.Logger, client batchClient, address common.Address) *LoggingFeeQuoterWriter {
	return &LoggingFeeQuoterWriter{lggr: lggr, client: client, address: address, decimals: make(map[common.Address]uint8)}
}

// UpdatePrices logs the updates and returns nil. It reads the token decimals and scales the token prices
// to the on-chain format. Gas prices are in USD per gas unit with 1e18 precision.
func (w *LoggingFeeQuoterWriter) UpdatePrices(ctx context.Context, tokenPrices []protocol.FeeTokenPriceUpdate, gasPrices []protocol.GasTokenPriceUpdate) error {
	tokenAddresses := make([]common.Address, len(tokenPrices))
	for i, update := range tokenPrices {
		tokenAddresses[i] = common.BytesToAddress(update.Address)
	}
	decimals, err := w.tokenDecimals(ctx, tokenAddresses)
	if err != nil {
		return err
	}
	scaledTokenPrices, err := scaleTokenPrices(tokenPrices, decimals)
	if err != nil {
		return err
	}
	formattedTokenPrices := make([]fee_quoter.InternalTokenPriceUpdate, len(scaledTokenPrices))
	for _, token := range scaledTokenPrices {
		formattedTokenPrice := fee_quoter.InternalTokenPriceUpdate{
			SourceToken: common.BytesToAddress(token.Address),
			UsdPerToken: (*big.Int)(token.Price),
		}
		formattedTokenPrices = append(formattedTokenPrices, formattedTokenPrice)
	}

	packedGasPrices := make([]fee_quoter.InternalGasPriceUpdate, len(gasPrices))
	for _, update := range scaleGasPrice(gasPrices) {
		// need to take the exec + da fee and combine according to
		packedGasPrice := packFeeComponents(update.USDGasPrice)
		formattedPrice := fee_quoter.InternalGasPriceUpdate{
			DestChainSelector: uint64(update.ChainSelector),
			UsdPerUnitGas:     packedGasPrice,
		}
		packedGasPrices = append(packedGasPrices, formattedPrice)
	}

	gasPriceUpdate := fee_quoter.InternalPriceUpdates{
		GasPriceUpdates:   packedGasPrices,
		TokenPriceUpdates: formattedTokenPrices,
	}

	w.lggr.Infow("Fee quoter price update not sent, the writer only logs",
		"feeQuoter", w.address.Hex(),
		"prices", gasPriceUpdate,
	)
	return nil
}

// tokenDecimals returns the decimals of the tokens. Cached decimals are not read again,
// and the others are read in one RPC batch.
func (w *LoggingFeeQuoterWriter) tokenDecimals(ctx context.Context, tokens []common.Address) (map[common.Address]uint8, error) {
	if w.client == nil && len(tokens) > 0 {
		return nil, errors.New("fee quoter writer has no client to read token decimals")
	}
	out := make(map[common.Address]uint8, len(tokens))
	var missing []common.Address
	w.mu.Lock()
	for _, token := range tokens {
		if cached, ok := w.decimals[token]; ok {
			out[token] = cached
		} else if _, queued := out[token]; !queued {
			out[token] = 0
			missing = append(missing, token)
		}
	}
	w.mu.Unlock()
	if len(missing) == 0 {
		return out, nil
	}

	fetched := make([]uint8, len(missing))
	batch := newCallBatch(w.client)
	for i, token := range missing {
		token20, err := erc20.NewERC20Caller(token, batch)
		if err != nil {
			return nil, err
		}
		batch.add(fmt.Sprintf("decimals(%s)", token), func() (err error) {
			fetched[i], err = token20.Decimals(&bind.CallOpts{Context: ctx})
			return err
		})
	}
	if err := batch.send(ctx); err != nil {
		return nil, fmt.Errorf("failed to read token decimals: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, token := range missing {
		w.decimals[token] = fetched[i]
		out[token] = fetched[i]
	}
	return out, nil
}

// scaleTokenPrices returns a copy of tokenPrices with each price scaled to the on-chain format,
// price * 1e18 / 10^decimals. The input slice is left unchanged.
//
// context token price updates are in the form USD per whole token, with 1e18 precision. These need
// to be normalized to e18 accounting for the token's decimals. This is the inverse of
// onChainTokenPriceToUSDPerWholeToken() in fee_quoter_reader.go
// https://github.com/smartcontractkit/chainlink-ccip/blob/ede0ec8b73e6e0dc32e317068c0a246d7aafc564/chains/evm/contracts/FeeQuoter.sol#L140
func scaleTokenPrices(tokenPrices []protocol.FeeTokenPriceUpdate, decimals map[common.Address]uint8) ([]protocol.FeeTokenPriceUpdate, error) {
	out := make([]protocol.FeeTokenPriceUpdate, len(tokenPrices))
	for i, update := range tokenPrices {
		token := common.BytesToAddress(update.Address)
		if update.Price == nil || (*big.Int)(update.Price).Sign() < 0 {
			return nil, fmt.Errorf("invalid price for token %s", token)
		}
		scaled := new(big.Int).Mul((*big.Int)(update.Price), pow10(uint(usdPrecisionDecimals)))
		scaled.Div(scaled, pow10(uint(decimals[token])))
		out[i] = protocol.FeeTokenPriceUpdate{Address: update.Address, Price: (*protocol.USDPerWholeToken)(scaled)}
	}
	return out, nil
}

// scaleGasPrice returns a copy of gasPrices with the execution and DA fees of Hedera
// updates divided by 1e10. Other chains and the input slice are left unchanged.
func scaleGasPrice(gasPrices []protocol.GasTokenPriceUpdate) []protocol.GasTokenPriceUpdate {
	out := make([]protocol.GasTokenPriceUpdate, len(gasPrices))
	for i, update := range gasPrices {
		out[i] = update
		if update.ChainSelector == protocol.ChainSelector(chainsel.HEDERA_MAINNET.Selector) ||
			update.ChainSelector == protocol.ChainSelector(chainsel.HEDERA_TESTNET.Selector) {
			out[i].USDGasPrice = protocol.USDGasPrice{
				ExecutionFee: scaleWeiBar(update.USDGasPrice.ExecutionFee),
				DAFee:        scaleWeiBar(update.USDGasPrice.DAFee),
			}
		}
	}
	return out
}

// hedera specific scaling due to eth gas price RPC call returning in e18 where the
// actual token is e8 precision
func scaleWeiBar(price *protocol.USDPerGasUnit) *protocol.USDPerGasUnit {
	if price == nil {
		return nil
	}
	return (*protocol.USDPerGasUnit)(new(big.Int).Div((*big.Int)(price), weibarPerTinybar))
}

// Pack fee components following existing implementation where DA fee is left shifted
// into a packed fee. Previous implementation is still being used for FQ 2.0.0 so logic
// still applies
// https://github.com/smartcontractkit/chainlink-ccip/blob/ede0ec8b73e6e0dc32e317068c0a246d7aafc564/commit/chainfee/outcome.go#L408
func packFeeComponents(feeComponents protocol.USDGasPrice) *big.Int {
	daShifted := new(big.Int).Lsh(feeComponents.DAFee.ToInt(), 112)
	return new(big.Int).Or(daShifted, feeComponents.ExecutionFee.ToInt())
}
