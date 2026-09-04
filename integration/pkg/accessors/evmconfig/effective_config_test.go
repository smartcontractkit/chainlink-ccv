package evmconfig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The projection the pre-cutover diff reads: what standalone will run per chain, through the same
// BuildChainlinkEVMTOML the runtime adapter uses.
func TestEffectiveChainConfigs(t *testing.T) {
	t.Parallel()

	t.Run("explicit settings are reported as configured", func(t *testing.T) {
		t.Parallel()
		conversion, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'
FinalityDepth = 22
FinalityTagEnabled = false
[EVM.Transactions.TransactionManagerV2]
BlockTime = '12s'

[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
WSURL = 'wss://sepolia.example.com'
Order = 5

[[EVM.Nodes]]
Name = 'backup'
HTTPURL = 'https://sepolia-backup.example.com'
`))
		require.NoError(t, err)

		chains, err := EffectiveChainConfigs(conversion.Config)
		require.NoError(t, err)
		chain := onlyChain(t, chains)

		assert.Equal(t, sepoliaChainID, chain.ChainID)
		assert.Equal(t, uint32(22), chain.FinalityDepth)
		assert.False(t, chain.FinalityTagEnabled)
		assert.Equal(t, "12s", chain.TXMBlockTime)
		assert.False(t, chain.TXMBlockTimeIsDefault)
		assert.False(t, chain.HeadTrackerPersistence, "standalone always runs the in-memory saver")

		require.Len(t, chain.Nodes, 2)
		assert.Equal(t, "primary", chain.Nodes[0].Name)
		assert.True(t, chain.Nodes[0].HasWebSocket)
		require.NotNil(t, chain.Nodes[0].Order)
		assert.Equal(t, int32(5), *chain.Nodes[0].Order)
		assert.Equal(t, "backup", chain.Nodes[1].Name)
		assert.False(t, chain.Nodes[1].HasWebSocket)
	})

	t.Run("an unset block time is flagged as the fallback", func(t *testing.T) {
		t.Parallel()
		conversion, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '` + sepoliaChainID + `'

[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://sepolia.example.com'
`))
		require.NoError(t, err)

		chains, err := EffectiveChainConfigs(conversion.Config)
		require.NoError(t, err)
		chain := onlyChain(t, chains)
		assert.Equal(t, DefaultTXMBlockTime.String(), chain.TXMBlockTime)
		assert.True(t, chain.TXMBlockTimeIsDefault,
			"the 2s fallback is the first thing to check on a slow chain, so the report must flag it")
	})

	t.Run("the standalone format projects without a conversion", func(t *testing.T) {
		t.Parallel()
		chains, err := EffectiveChainConfigs(Config{Chains: map[string]ChainConfig{
			sepoliaSelector: {
				FinalityDepth: 30,
				TXMBlockTime:  12 * time.Second,
				Nodes:         []Node{{Name: "primary", HTTPUrl: "https://sepolia.example.com"}},
			},
		}})
		require.NoError(t, err)
		chain := onlyChain(t, chains)
		assert.Equal(t, uint32(30), chain.FinalityDepth)
		assert.Equal(t, "12s", chain.TXMBlockTime)
		assert.False(t, chain.TXMBlockTimeIsDefault)
	})
}

// onlyChain returns the single chain of a one-chain projection.
func onlyChain(t *testing.T, chains map[string]EffectiveChain) EffectiveChain {
	t.Helper()
	require.Len(t, chains, 1)
	for _, chain := range chains {
		return chain
	}
	t.Fatal("expected at least one chain")
	return EffectiveChain{}
}
