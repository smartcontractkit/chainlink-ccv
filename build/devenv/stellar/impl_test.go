package stellar

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewChain(t *testing.T) {
	logger := zerolog.Nop()
	chain := New(logger)
	require.NotNil(t, chain)
	assert.Equal(t, FamilyStellar, chain.ChainFamily())
}

func TestStellarAddress(t *testing.T) {
	// Test that stellarAddress creates proper padded addresses
	addr := stellarAddress("test")
	assert.Len(t, addr, stellarAddressLen)
	// Should be padded with 's' characters on the left
	assert.Equal(t, byte('s'), addr[0])
	// The actual name should be at the end
	assert.Equal(t, []byte("test"), addr[stellarAddressLen-4:])
}
