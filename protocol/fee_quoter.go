package protocol

import (
	"math/big"
	"time"
)

// WholeNativeTokenPerGasUnit is a gas price in whole native tokens per gas unit, with 1e36 precision.
// Each chain family applies its own native token decimals to produce it.
type WholeNativeTokenPerGasUnit big.Int

// ToInt returns the price as a *big.ToInt.
func (p *WholeNativeTokenPerGasUnit) ToInt() *big.Int { return (*big.Int)(p) }

// USDPerGasUnit is a gas price in USD per gas unit, with 1e18 precision.
type USDPerGasUnit big.Int

// ToInt returns the price as a *big.ToInt.
func (p *USDPerGasUnit) ToInt() *big.Int { return (*big.Int)(p) }

// USDPerWholeToken is a token price in USD per whole token, with 1e18 precision.
// Each chain family converts to and from its on-chain format using the token's decimals.
type USDPerWholeToken big.Int

// ToInt returns the price as a *big.ToInt.
func (p *USDPerWholeToken) ToInt() *big.Int { return (*big.Int)(p) }

// NativeGasPrice is a chain's gas price in its native token, split into
// execution and data availability (DA) fees.
type NativeGasPrice struct {
	// ExecutionFee is the base execution fee.
	ExecutionFee *WholeNativeTokenPerGasUnit
	// DAFee is the data availability fee, if the chain has one.
	DAFee *WholeNativeTokenPerGasUnit
}

// USDGasPrice is a gas price in USD, split into execution and data availability
// (DA) fees.
type USDGasPrice struct {
	// ExecutionFee is the base execution fee.
	ExecutionFee *USDPerGasUnit
	// DAFee is the data availability fee, if the chain has one.
	DAFee *USDPerGasUnit
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
	// Price is the token's price.
	Price *USDPerWholeToken
	// UpdatedAt is when the price was last updated on-chain.
	UpdatedAt time.Time
}

// GasTokenPrice is a chain's gas price and when it was updated.
type GasTokenPrice struct {
	// USDGasPrice is the chain's gas price.
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
	// Price is the new price for the token.
	Price *USDPerWholeToken
}

// GasTokenPriceUpdate is a requested gas price update for a destination chain.
type GasTokenPriceUpdate struct {
	// ChainSelector is the destination chain to update.
	ChainSelector ChainSelector
	// USDGasPrice is the new gas price for the chain.
	USDGasPrice USDGasPrice
}
