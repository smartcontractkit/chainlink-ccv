package pricereader

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/fee_quoter"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/erc20"
)

const (
	// packedGasPriceBits is Internal.GAS_PRICE_BITS in Internal.sol. No Go binding exposes it.
	packedGasPriceBits = 112
	// usdPrecisionDecimals is the precision of the USD prices (1e18).
	usdPrecisionDecimals = 18
)

var _ chainaccess.FeeQuoterReader = (*EVMFeeQuoterReader)(nil)

// EVMFeeQuoterReader reads the state of a Fee Quoter contract.
type EVMFeeQuoterReader struct {
	address common.Address
	client  batchClient

	mu     sync.Mutex
	self   []common.Address
	tokens *TokenMetadataCache
}

// ReaderOption configures an EVMFeeQuoterReader.
type ReaderOption func(*EVMFeeQuoterReader)

// WithReaderTokenCache makes the reader use a token metadata cache shared with other components.
func WithReaderTokenCache(cache *TokenMetadataCache) ReaderOption {
	return func(f *EVMFeeQuoterReader) { f.tokens = cache }
}

// NewEVMFeeQuoterReader creates a Fee Quoter reader. It does not call the chain.
// The self addresses are the price updater keys. Use SetServiceAddresses when the keystore is available later.
func NewEVMFeeQuoterReader(address common.Address, client batchClient, self []common.Address, opts ...ReaderOption) (*EVMFeeQuoterReader, error) {
	if client == nil {
		return nil, errors.New("batch client is nil")
	}
	f := &EVMFeeQuoterReader{
		address: address,
		client:  client,
		self:    slices.Clone(self),
		tokens:  NewTokenMetadataCache(),
	}
	for _, opt := range opts {
		opt(f)
	}
	return f, nil
}

// SetServiceAddresses sets the addresses that GetFQState looks for in the authorized callers.
func (f *EVMFeeQuoterReader) SetServiceAddresses(self []common.Address) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.self = slices.Clone(self)
}

// GetFQState reads the state of the Fee Quoter at one block, with a maximum of three RPC requests:
// the block number, then one batch for the structure and one for the prices, both pinned to that block.
func (f *EVMFeeQuoterReader) GetFQState(ctx context.Context) (protocol.FQState, error) {
	f.mu.Lock()
	self := slices.Clone(f.self)
	f.mu.Unlock()

	blockNumber, err := f.readBlockNumber(ctx)
	if err != nil {
		return protocol.FQState{}, err
	}
	structure, err := f.readStructure(ctx, blockNumber)
	if err != nil {
		return protocol.FQState{}, err
	}
	prices, err := f.readPrices(ctx, structure)
	if err != nil {
		return protocol.FQState{}, err
	}

	state := protocol.FQState{
		FeeTokens:           make([]protocol.FeeToken, 0, len(structure.tokens)),
		FeeTokenPrices:      make(map[string]protocol.FeeTokenPrice, len(structure.tokens)),
		DestinationChains:   make([]protocol.ChainSelector, 0, len(structure.destSelectors)),
		GasPrices:           make(map[protocol.ChainSelector]protocol.GasTokenPrice, len(structure.destSelectors)),
		ServiceIsAuthorized: slices.ContainsFunc(self, func(a common.Address) bool { return slices.Contains(structure.callers, a) }),
	}
	for i, token := range structure.tokens {
		address := protocol.UnknownAddress(token.Bytes())
		metadata := prices.metadata[token]
		state.FeeTokens = append(state.FeeTokens, protocol.FeeToken{Address: address, Symbol: metadata.symbol})
		// A zero timestamp means that the token has no price on chain.
		if prices.tokenPrices[i].Timestamp == 0 {
			continue
		}
		state.FeeTokenPrices[address.String()] = protocol.FeeTokenPrice{
			Price:     onChainTokenPriceToUSDPerWholeToken(prices.tokenPrices[i].Value, metadata.decimals),
			UpdatedAt: time.Unix(int64(prices.tokenPrices[i].Timestamp), 0),
		}
	}
	for i, selector := range structure.destSelectors {
		chainSelector := protocol.ChainSelector(selector)
		state.DestinationChains = append(state.DestinationChains, chainSelector)
		if prices.gasPrices[i].Timestamp == 0 {
			continue
		}
		state.GasPrices[chainSelector] = protocol.GasTokenPrice{
			USDGasPrice: unpackGasPrice(prices.gasPrices[i].Value),
			UpdatedAt:   time.Unix(int64(prices.gasPrices[i].Timestamp), 0),
		}
	}
	return state, nil
}

type fqStructure struct {
	tokens        []common.Address
	destSelectors []uint64
	callers       []common.Address
	blockNumber   *big.Int
}

// readBlockNumber reads the block that pins all other reads. Calls in one batch can see different heads,
// so the block number is not read in the same batch as the other calls.
func (f *EVMFeeQuoterReader) readBlockNumber(ctx context.Context) (*big.Int, error) {
	blockNumber, err := f.client.LatestBlockHeight(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read the latest block number: %w", err)
	}
	return blockNumber, nil
}

// readStructure reads the fee tokens, the destination chains and the authorized callers at blockNumber.
func (f *EVMFeeQuoterReader) readStructure(ctx context.Context, blockNumber *big.Int) (fqStructure, error) {
	out := fqStructure{blockNumber: blockNumber}
	batch := newCallBatch(f.client)
	fq, err := fee_quoter.NewFeeQuoterCaller(f.address, batch)
	if err != nil {
		return fqStructure{}, err
	}
	opts := &bind.CallOpts{Context: ctx, BlockNumber: blockNumber}
	batch.add("getFeeTokens", func() (err error) {
		out.tokens, err = fq.GetFeeTokens(opts)
		return err
	})
	batch.add("getAllDestChainConfigs", func() (err error) {
		out.destSelectors, _, err = fq.GetAllDestChainConfigs(opts)
		return err
	})
	batch.add("getAllAuthorizedCallers", func() (err error) {
		out.callers, err = fq.GetAllAuthorizedCallers(opts)
		return err
	})
	if err := batch.send(ctx); err != nil {
		return fqStructure{}, err
	}
	return out, nil
}

type fqPrices struct {
	tokenPrices []fee_quoter.InternalTimestampedPackedUint224
	gasPrices   []fee_quoter.InternalTimestampedPackedUint224
	metadata    map[common.Address]tokenMetadata
}

// readPrices reads the token prices, the gas prices and the metadata of tokens that are not cached, at the same block.
func (f *EVMFeeQuoterReader) readPrices(ctx context.Context, structure fqStructure) (fqPrices, error) {
	out := fqPrices{
		gasPrices: make([]fee_quoter.InternalTimestampedPackedUint224, len(structure.destSelectors)),
		metadata:  make(map[common.Address]tokenMetadata, len(structure.tokens)),
	}
	batch := newCallBatch(f.client)
	fq, err := fee_quoter.NewFeeQuoterCaller(f.address, batch)
	if err != nil {
		return fqPrices{}, err
	}
	opts := &bind.CallOpts{Context: ctx, BlockNumber: structure.blockNumber}

	if len(structure.tokens) > 0 {
		batch.add("getTokenPrices", func() (err error) {
			out.tokenPrices, err = fq.GetTokenPrices(opts, structure.tokens)
			return err
		})
	}
	for i, selector := range structure.destSelectors {
		batch.add(fmt.Sprintf("getDestinationChainGasPrice(%d)", selector), func() (err error) {
			out.gasPrices[i], err = fq.GetDestinationChainGasPrice(opts, selector)
			return err
		})
	}
	// Decimals and symbol never change, so each is read only once.
	missingDecimals, missingSymbols := f.uncachedTokens(structure.tokens, out.metadata)
	fetchedDecimals := make([]uint8, len(missingDecimals))
	fetchedSymbols := make([]string, len(missingSymbols))
	for i, token := range missingDecimals {
		token20, err := erc20.NewERC20Caller(token, batch)
		if err != nil {
			return fqPrices{}, err
		}
		batch.add(fmt.Sprintf("decimals(%s)", token), func() (err error) {
			fetchedDecimals[i], err = token20.Decimals(opts)
			return err
		})
	}
	for i, token := range missingSymbols {
		token20, err := erc20.NewERC20Caller(token, batch)
		if err != nil {
			return fqPrices{}, err
		}
		batch.add(fmt.Sprintf("symbol(%s)", token), func() (err error) {
			fetchedSymbols[i], err = token20.Symbol(opts)
			return err
		})
	}

	if err := batch.send(ctx); err != nil {
		return fqPrices{}, err
	}
	if len(out.tokenPrices) != len(structure.tokens) {
		return fqPrices{}, fmt.Errorf("fee quoter returned %d token prices for %d tokens", len(out.tokenPrices), len(structure.tokens))
	}
	for i, token := range missingDecimals {
		f.tokens.setDecimals(token, fetchedDecimals[i])
		m := out.metadata[token]
		m.decimals = fetchedDecimals[i]
		out.metadata[token] = m
	}
	for i, token := range missingSymbols {
		f.tokens.setSymbol(token, fetchedSymbols[i])
		m := out.metadata[token]
		m.symbol = fetchedSymbols[i]
		out.metadata[token] = m
	}
	return out, nil
}

// uncachedTokens adds the cached metadata of tokens to metadata and returns the tokens whose decimals
// and whose symbol are not cached, without duplicates.
func (f *EVMFeeQuoterReader) uncachedTokens(tokens []common.Address, metadata map[common.Address]tokenMetadata) (decimals, symbols []common.Address) {
	for _, token := range tokens {
		m := metadata[token]
		if v, ok := f.tokens.getDecimals(token); ok {
			m.decimals = v
		} else if !slices.Contains(decimals, token) {
			decimals = append(decimals, token)
		}
		if v, ok := f.tokens.getSymbol(token); ok {
			m.symbol = v
		} else if !slices.Contains(symbols, token) {
			symbols = append(symbols, token)
		}
		metadata[token] = m
	}
	return decimals, symbols
}

// onChainTokenPriceToUSDPerWholeToken converts USD per 1e18 smallest units (1e18 precision)
// to USD per whole token (1e18 precision): price * 10^decimals / 1e18.
func onChainTokenPriceToUSDPerWholeToken(price *big.Int, decimals uint8) *protocol.USDPerWholeToken {
	scaled := new(big.Int).Mul(price, pow10(uint(decimals)))
	return (*protocol.USDPerWholeToken)(scaled.Div(scaled, pow10(usdPrecisionDecimals)))
}

// unpackGasPrice splits a packed gas price: the DA part is in the high bits, the execution part in the low bits.
func unpackGasPrice(packed *big.Int) protocol.USDGasPrice {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), packedGasPriceBits), big.NewInt(1))
	return protocol.USDGasPrice{
		ExecutionFee: (*protocol.USDPerGasUnit)(new(big.Int).And(packed, mask)),
		DAFee:        (*protocol.USDPerGasUnit)(new(big.Int).Rsh(packed, packedGasPriceBits)),
	}
}
