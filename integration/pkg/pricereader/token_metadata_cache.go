package pricereader

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

type tokenMetadata struct {
	decimals uint8
	symbol   string
}

// TokenMetadataCache holds token decimals and symbols, which never change once read.
// The Fee Quoter reader and writer of a chain share one so each value is read once.
type TokenMetadataCache struct {
	mu       sync.Mutex
	decimals map[common.Address]uint8
	symbols  map[common.Address]string
}

func NewTokenMetadataCache() *TokenMetadataCache {
	return &TokenMetadataCache{
		decimals: make(map[common.Address]uint8),
		symbols:  make(map[common.Address]string),
	}
}

func (c *TokenMetadataCache) getDecimals(token common.Address) (uint8, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.decimals[token]
	return v, ok
}

func (c *TokenMetadataCache) setDecimals(token common.Address, v uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decimals[token] = v
}

func (c *TokenMetadataCache) getSymbol(token common.Address) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.symbols[token]
	return v, ok
}

func (c *TokenMetadataCache) setSymbol(token common.Address, v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.symbols[token] = v
}
