package protocol

import (
	"math/big"
	"time"
)

// Token is the SoT symbol identifying a fee token.
type Token string

// GasPrice represents the gas price for a chain, split into execution and data
// availability (DA) fees.
type GasPrice struct {
	// ExecutionFee is the base execution fee.
	ExecutionFee *big.Int
	// DAFee is the data availability fee, if the chain has one.
	DAFee *big.Int
}

// FeeToken is a fee token and its on-chain address.
type FeeToken struct {
	// Token is the SoT symbol identifying the fee token.
	Token Token
	// Address is the on-chain address of the fee token.
	Address UnknownAddress
}

// FeeTokenPrice is a fee token's price and when it was updated.
type FeeTokenPrice struct {
	// Price is the token's price.
	Price *big.Int
	// UpdatedAt is when the price was last updated on-chain.
	UpdatedAt time.Time
}

// GasTokenPrice is a chain's gas price and when it was updated.
type GasTokenPrice struct {
	// GasPrice is the chain's gas price.
	GasPrice GasPrice
	// UpdatedAt is when the gas price was last updated on-chain.
	UpdatedAt time.Time
}

// FQState stores the Fee Quoter on-chain state.
type FQState struct {
	// FeeTokens is the list of fee tokens and their addresses.
	FeeTokens []FeeToken
	// FeeTokenPrices maps a token to its price and when it was updated.
	FeeTokenPrices map[Token]FeeTokenPrice
	// DestinationChains is the list of destination chain selectors.
	DestinationChains []ChainSelector
	// GasPrices maps a chain selector to its gas price and when it was updated.
	GasPrices map[ChainSelector]GasTokenPrice
	// ServiceIsAuthorized indicates whether the pricer is an authorized caller.
	ServiceIsAuthorized bool
}

// FeeTokenPriceUpdate is a requested price update for a fee token.
type FeeTokenPriceUpdate struct {
	// Address is the on-chain address of the fee token to update.
	Address UnknownAddress
	// Price is the new price for the token.
	Price *big.Int
}

// GasTokenPriceUpdate is a requested gas price update for a destination chain.
type GasTokenPriceUpdate struct {
	// ChainSelector is the destination chain to update.
	ChainSelector ChainSelector
	// GasPrice is the new gas price for the chain.
	GasPrice GasPrice
}
