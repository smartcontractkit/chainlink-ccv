package protocol

import (
	"math/big"
	"time"
)

// NativeGasPrice is a chain's gas price in its native token, split into
// execution and data availability (DA) fees. Values are normalized to the
// smallest native token unit per gas unit, with 1e36 precision.
type NativeGasPrice struct {
	// ExecutionFee is the base execution fee, in smallest native token units
	// per gas unit, with 1e36 precision.
	ExecutionFee *big.Int
	// DAFee is the data availability fee, if the chain has one, in smallest
	// native token units per gas unit, with 1e36 precision.
	DAFee *big.Int
}

// USDGasPrice is a gas price in USD, split into execution and data availability
// (DA) fees.
type USDGasPrice struct {
	// ExecutionFee is the base execution fee, in 1e18 USD per gas unit.
	ExecutionFee *big.Int
	// DAFee is the data availability fee, if the chain has one, in 1e18 USD per
	// gas unit.
	DAFee *big.Int
}

// FeeToken is a fee token and its on-chain address.
type FeeToken struct {
	// Address is the on-chain address of the fee token.
	Address UnknownAddress
	// Symbol is the fee token's on-chain symbol, empty on chains without one.
	Symbol string
}

// FeeTokenPrice is a fee token's price and when it was updated.
type FeeTokenPrice struct {
	// Price is the token's price, in 1e18 USD per 1e18 smallest token units.
	Price *big.Int
	// UpdatedAt is when the price was last updated on-chain.
	UpdatedAt time.Time
}

// GasTokenPrice is a chain's gas price and when it was updated.
type GasTokenPrice struct {
	// USDGasPrice is the chain's gas price, in 1e18 USD per gas unit.
	USDGasPrice USDGasPrice
	// UpdatedAt is when the gas price was last updated on-chain.
	UpdatedAt time.Time
}

// FQState stores the Fee Quoter on-chain state.
type FQState struct {
	// FeeTokens is the list of fee tokens and their addresses.
	FeeTokens []FeeToken
	// FeeTokenPrices maps a fee token address to its price and when it was
	// updated.
	FeeTokenPrices map[string]FeeTokenPrice
	// DestinationChains is the list of destination chain selectors.
	DestinationChains []ChainSelector
	// GasPrices maps a chain selector to its gas price and when it was updated.
	GasPrices map[ChainSelector]GasTokenPrice
	// ServiceIsAuthorized indicates whether the service is an authorized caller.
	ServiceIsAuthorized bool
}

// FeeTokenPriceUpdate is a requested price update for a fee token.
type FeeTokenPriceUpdate struct {
	// Address is the on-chain address of the fee token to update.
	Address UnknownAddress
	// Price is the new price for the token, in 1e18 USD per 1e18 smallest token
	// units.
	Price *big.Int
}

// GasTokenPriceUpdate is a requested gas price update for a destination chain.
type GasTokenPriceUpdate struct {
	// ChainSelector is the destination chain to update.
	ChainSelector ChainSelector
	// USDGasPrice is the new gas price for the chain, in 1e18 USD per gas unit.
	USDGasPrice USDGasPrice
}
