package stellar

import (
	"testing"

	"github.com/rs/zerolog"
	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewChain(t *testing.T) {
	logger := zerolog.Nop()
	chain := New(logger)
	require.NotNil(t, chain)
	assert.Equal(t, chainsel.FamilyStellar, chain.ChainFamily())
}

func TestGenerateContractAddress(t *testing.T) {
	networkPassphrase := "Test SDF Network ; September 2015"

	// Test that generateContractAddress creates proper 32-byte addresses
	addr := generateContractAddress("test-contract", networkPassphrase)
	assert.Len(t, addr, stellarAddressLen)

	// Test determinism - same inputs should produce same output
	addr2 := generateContractAddress("test-contract", networkPassphrase)
	assert.Equal(t, addr, addr2)

	// Test that different names produce different addresses
	addr3 := generateContractAddress("other-contract", networkPassphrase)
	assert.NotEqual(t, addr, addr3)

	// Test that different network passphrases produce different addresses
	addr4 := generateContractAddress("test-contract", "Public Global Stellar Network ; September 2015")
	assert.NotEqual(t, addr, addr4)
}

func TestGenerateAccountAddress(t *testing.T) {
	// Test that generateAccountAddress creates valid Stellar addresses
	addr, err := generateAccountAddress("test-seed")
	require.NoError(t, err)

	// Stellar account addresses start with 'G'
	assert.True(t, len(addr) == 56, "Stellar address should be 56 characters")
	assert.Equal(t, byte('G'), addr[0], "Stellar account address should start with G")

	// Test determinism - same seed should produce same address
	addr2, err := generateAccountAddress("test-seed")
	require.NoError(t, err)
	assert.Equal(t, addr, addr2)

	// Test that different seeds produce different addresses
	addr3, err := generateAccountAddress("other-seed")
	require.NoError(t, err)
	assert.NotEqual(t, addr, addr3)
}
