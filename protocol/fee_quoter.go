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

// TokenPrice is a token's price and when it was updated.
type TokenPrice struct {
	// Price is the token's price.
	Price *big.Int
	// UpdatedAt is when the price was last updated on-chain.
	UpdatedAt time.Time
}

// GasPriceUpdate is a chain's gas price and when it was updated.
type GasPriceUpdate struct {
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
	FeeTokenPrices map[Token]TokenPrice
	// DestinationChains is the list of destination chain selectors.
	DestinationChains []ChainSelector
	// GasPrices maps a chain selector to its gas price and when it was updated.
	GasPrices map[ChainSelector]GasPriceUpdate
	// ServiceIsAuthorized indicates whether the pricer is an authorized caller.
	ServiceIsAuthorized bool
}

// TokenPriceUpdate is a requested price update for a fee token, keyed by its
// on-chain address. The address is used because the Fee Quoter interface has no
// Token-to-address mapping of its own.
type TokenPriceUpdate struct {
	// Address is the on-chain address of the fee token to update.
	Address UnknownAddress
	// Price is the new price for the token.
	Price *big.Int
}
