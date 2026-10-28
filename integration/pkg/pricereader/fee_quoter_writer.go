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
	"github.com/smartcontractkit/chainlink-evm/pkg/keys"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"

	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
	txmgrcommon "github.com/smartcontractkit/chainlink-framework/chains/txmgr"
)

const (
	// updatePricesBaseGas and updatePricesGasPerUpdate bound the gas limit of an updatePrices call.
	updatePricesBaseGas      = 100_000
	updatePricesGasPerUpdate = 50_000
)

var feeQuoterABI = evmtypes.MustGetABI(fee_quoter.FeeQuoterABI)

// weibarPerTinybar is the divisor applied to Hedera gas prices.
// Hedera gas price RPC call returns 1e18 yet the atomic unit
// for the actual token is 1e8. Gas prices need to be scaled down
// by this factor.
var weibarPerTinybar = big.NewInt(1e10)

var _ chainaccess.FeeQuoterWriter = (*EVMFeeQuoterWriter)(nil)

// EVMFeeQuoterWriter sends price updates to the Fee Quoter through the transaction manager.
// Without a transaction manager (see WithTxm) it only logs the updates.
type EVMFeeQuoterWriter struct {
	lggr    logger.Logger
	client  batchClient
	address common.Address

	txm           txmgr.TxManager
	keys          keys.RoundRobin
	fromAddresses []common.Address

	mu       sync.Mutex
	decimals map[common.Address]uint8
}

// WriterOption configures an EVMFeeQuoterWriter.
type WriterOption func(*EVMFeeQuoterWriter)

// WithTxm makes the writer send its updates as transactions from the given addresses.
func WithTxm(txm txmgr.TxManager, keys keys.RoundRobin, fromAddresses []common.Address) WriterOption {
	return func(w *EVMFeeQuoterWriter) {
		w.txm = txm
		w.keys = keys
		w.fromAddresses = fromAddresses
	}
}

// NewEVMFeeQuoterWriter creates a writer. It does not call the chain.
func NewEVMFeeQuoterWriter(lggr logger.Logger, client batchClient, address common.Address, opts ...WriterOption) *EVMFeeQuoterWriter {
	w := &EVMFeeQuoterWriter{lggr: lggr, client: client, address: address, decimals: make(map[common.Address]uint8)}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// UpdatePrices reads the token decimals, scales the token prices to the on-chain format and submits one
// updatePrices transaction to the TXM, returning once it is accepted. Without a TXM it only logs.
// Gas prices are in USD per gas unit with 1e18 precision.
func (w *EVMFeeQuoterWriter) UpdatePrices(ctx context.Context, tokenPrices []protocol.FeeTokenPriceUpdate, gasPrices []protocol.GasTokenPriceUpdate) error {
	if len(tokenPrices) == 0 && len(gasPrices) == 0 {
		return nil
	}
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
	formattedTokenPrices := make([]fee_quoter.InternalTokenPriceUpdate, 0, len(scaledTokenPrices))
	for _, token := range scaledTokenPrices {
		formattedTokenPrices = append(formattedTokenPrices, fee_quoter.InternalTokenPriceUpdate{
			SourceToken: common.BytesToAddress(token.Address),
			UsdPerToken: (*big.Int)(token.Price),
		})
	}

	scaledGasPrices := scaleGasPrice(gasPrices)
	packedGasPrices := make([]fee_quoter.InternalGasPriceUpdate, 0, len(scaledGasPrices))
	for _, update := range scaledGasPrices {
		packedGasPrices = append(packedGasPrices, fee_quoter.InternalGasPriceUpdate{
			DestChainSelector: uint64(update.ChainSelector),
			UsdPerUnitGas:     packFeeComponents(update.USDGasPrice),
		})
	}

	priceUpdates := fee_quoter.InternalPriceUpdates{
		GasPriceUpdates:   packedGasPrices,
		TokenPriceUpdates: formattedTokenPrices,
	}
	if w.txm == nil {
		w.lggr.Infow("Fee quoter price update not sent, the writer has no transaction manager",
			"feeQuoter", w.address.Hex(),
			"prices", priceUpdates,
		)
		return nil
	}
	return w.send(ctx, priceUpdates)
}

// send submits updatePrices to the TXM. It does not wait for the transaction to be mined.
func (w *EVMFeeQuoterWriter) send(ctx context.Context, priceUpdates fee_quoter.InternalPriceUpdates) error {
	payload, err := feeQuoterABI.Pack("updatePrices", priceUpdates)
	if err != nil {
		return fmt.Errorf("failed to abi encode updatePrices: %w", err)
	}
	from, err := w.keys.GetNextAddress(ctx, w.fromAddresses...)
	if err != nil {
		return fmt.Errorf("failed to pick a sender address: %w", err)
	}
	updates := uint64(len(priceUpdates.TokenPriceUpdates) + len(priceUpdates.GasPriceUpdates))
	tx, err := w.txm.CreateTransaction(ctx, txmgr.TxRequest{
		FromAddress:    from,
		ToAddress:      w.address,
		EncodedPayload: payload,
		FeeLimit:       updatePricesBaseGas + updatePricesGasPerUpdate*updates,
		Strategy:       txmgrcommon.NewSendEveryStrategy(),
	})
	if err != nil {
		return fmt.Errorf("failed to create updatePrices transaction: %w", err)
	}
	w.lggr.Infow("Submitted fee quoter price update to txm",
		"feeQuoter", w.address.Hex(),
		"tokenUpdates", len(priceUpdates.TokenPriceUpdates),
		"gasUpdates", len(priceUpdates.GasPriceUpdates),
		"txm key", tx.IdempotencyKey,
	)
	return nil
}

// tokenDecimals returns the decimals of the tokens. Cached decimals are not read again,
// and the others are read in one RPC batch.
func (w *EVMFeeQuoterWriter) tokenDecimals(ctx context.Context, tokens []common.Address) (map[common.Address]uint8, error) {
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
// actual token is e8 precision.
func scaleWeiBar(price *protocol.USDPerGasUnit) *protocol.USDPerGasUnit {
	if price == nil {
		return nil
	}
	return (*protocol.USDPerGasUnit)(new(big.Int).Div((*big.Int)(price), weibarPerTinybar))
}

// Pack fee components following existing implementation where DA fee is left shifted
// into a packed fee. Previous implementation is still being used for FQ 2.0.0 so logic
// still applies.
// https://github.com/smartcontractkit/chainlink-ccip/blob/ede0ec8b73e6e0dc32e317068c0a246d7aafc564/commit/chainfee/outcome.go#L408
func packFeeComponents(feeComponents protocol.USDGasPrice) *big.Int {
	da, execution := new(big.Int), new(big.Int)
	if feeComponents.DAFee != nil {
		da.Set(feeComponents.DAFee.ToInt())
	}
	if feeComponents.ExecutionFee != nil {
		execution.Set(feeComponents.ExecutionFee.ToInt())
	}
	return new(big.Int).Or(da.Lsh(da, packedGasPriceBits), execution)
}
