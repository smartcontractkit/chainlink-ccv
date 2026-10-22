package evm

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestChainGuard(t *testing.T) {
	t.Parallel()

	t.Run("second acquire for a held chain names both selectors and the chain ID", func(t *testing.T) {
		t.Parallel()
		g := newChainGuard()
		require.NoError(t, g.acquire("1337", protocol.ChainSelector(11)))

		err := g.acquire("1337", protocol.ChainSelector(22))
		require.ErrorContains(t, err, "evm_chain_id 1337")
		require.ErrorContains(t, err, "selector 11")
		require.ErrorContains(t, err, "selector 22")
	})

	t.Run("different chains do not block each other", func(t *testing.T) {
		t.Parallel()
		g := newChainGuard()
		require.NoError(t, g.acquire("1", protocol.ChainSelector(1)))
		require.NoError(t, g.acquire("2", protocol.ChainSelector(2)))
	})

	t.Run("release frees the chain, and only for its holder", func(t *testing.T) {
		t.Parallel()
		g := newChainGuard()
		require.NoError(t, g.acquire("1", protocol.ChainSelector(1)))

		g.release("1", protocol.ChainSelector(2))
		require.Error(t, g.acquire("1", protocol.ChainSelector(3)), "another selector cannot release the chain")

		g.release("1", protocol.ChainSelector(1))
		g.release("1", protocol.ChainSelector(1)) // repeating is harmless
		require.NoError(t, g.acquire("1", protocol.ChainSelector(2)))
		g.release("1", protocol.ChainSelector(1))
		require.Error(t, g.acquire("1", protocol.ChainSelector(3)), "a stale release must not free the new holder")
	})

	t.Run("exactly one of many concurrent acquires wins", func(t *testing.T) {
		t.Parallel()
		g := newChainGuard()
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := range 32 {
			wg.Go(func() {
				if err := g.acquire("1", protocol.ChainSelector(i)); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		require.Equal(t, 1, wins)
	})
}
