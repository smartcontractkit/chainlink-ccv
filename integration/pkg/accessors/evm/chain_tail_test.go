package evm

import (
	"context"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// fakeChain builds a deterministic hash-linked chain; fork changes the hashes from forkAt up.
type fakeChain struct {
	headers map[uint64]protocol.BlockHeader
}

func hashFor(num uint64, variant byte) protocol.Bytes32 {
	var h protocol.Bytes32
	h[0] = variant
	h[31] = byte(num)
	h[30] = byte(num >> 8)
	return h
}

func newFakeChain(top, forkAt uint64, variant byte) *fakeChain {
	c := &fakeChain{headers: map[uint64]protocol.BlockHeader{}}
	for n := uint64(0); n <= top; n++ {
		v, pv := byte(1), byte(1)
		if n >= forkAt {
			v = variant
		}
		if n-1 >= forkAt {
			pv = variant
		}
		c.headers[n] = protocol.BlockHeader{Number: n, Hash: hashFor(n, v), ParentHash: hashFor(n-1, pv)}
	}
	return c
}

func (c *fakeChain) GetBlocksHeaders(_ context.Context, nums []*big.Int) (map[uint64]protocol.BlockHeader, error) {
	out := map[uint64]protocol.BlockHeader{}
	for _, n := range nums {
		if h, ok := c.headers[n.Uint64()]; ok {
			out[h.Number] = h
		}
	}
	return out, nil
}

// noForkHeight is a fork height no fixture chain reaches, i.e. "never forked".
const noForkHeight = uint64(1) << 40

func TestChainTail(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	noFork := noForkHeight

	t.Run("steady state reads only new blocks", func(t *testing.T) {
		c := newFakeChain(200, noFork, 1)
		tail, err := newChainTail(c, lggr)
		require.NoError(t, err)
		fin := c.headers[50]
		changed, err := tail.advance(ctx, new(c.headers[100]), &fin)
		require.NoError(t, err)
		require.True(t, changed, "the first call seeds the tail and vouches for nothing")

		// head advances 100 -> 108, finality unchanged: the tail links the new blocks on.
		changed, err = tail.advance(ctx, new(c.headers[108]), &fin)
		require.NoError(t, err)
		require.False(t, changed)

		// no movement at all.
		changed, err = tail.advance(ctx, new(c.headers[108]), &fin)
		require.NoError(t, err)
		require.False(t, changed)
	})

	t.Run("deep reorg resolved entirely between polls is caught", func(t *testing.T) {
		c := newFakeChain(200, noFork, 1)
		tail, err := newChainTail(c, lggr)
		require.NoError(t, err)
		fin := c.headers[50]
		_, err = tail.advance(ctx, new(c.headers[100]), &fin)
		require.NoError(t, err)

		// Chain reorgs 30 deep (from block 70) AND re-extends to 110 before the next poll.
		// Only the new head is ever observed; every intermediate state was missed.
		forked := newFakeChain(200, 70, 9)
		tail.fetcher = forked
		changed, err := tail.advance(ctx, new(forked.headers[110]), &fin)
		require.NoError(t, err)
		require.True(t, changed, "must detect the reorg from the head link alone")
	})

	t.Run("lagging rpc node does not reseed", func(t *testing.T) {
		c := newFakeChain(200, noFork, 1)
		tail, err := newChainTail(c, lggr)
		require.NoError(t, err)
		fin := c.headers[50]
		_, err = tail.advance(ctx, new(c.headers[100]), &fin)
		require.NoError(t, err)
		changed, err := tail.advance(ctx, new(c.headers[95]), &fin) // node hop, same fork
		require.NoError(t, err)
		require.False(t, changed)
		require.Equal(t, uint64(100), tail.headers[len(tail.headers)-1].Number,
			"tail must be preserved")
	})

	t.Run("anchor advances with finality", func(t *testing.T) {
		c := newFakeChain(200, noFork, 1)
		tail, err := newChainTail(c, lggr)
		require.NoError(t, err)
		fin := c.headers[50]
		_, err = tail.advance(ctx, new(c.headers[100]), &fin)
		require.NoError(t, err)
		newFin := c.headers[90]
		_, err = tail.advance(ctx, new(c.headers[101]), &newFin)
		require.NoError(t, err)
		require.Equal(t, uint64(90), tail.headers[0].Number)
		require.Len(t, tail.headers, 12)
	})

	t.Run("finality violation drops the tail", func(t *testing.T) {
		c := newFakeChain(200, noFork, 1)
		tail, err := newChainTail(c, lggr)
		require.NoError(t, err)
		fin := c.headers[50]
		_, err = tail.advance(ctx, new(c.headers[100]), &fin)
		require.NoError(t, err)
		bad := c.headers[60]
		bad.Hash = hashFor(60, 42) // finalized block changed hash
		_, err = tail.advance(ctx, new(c.headers[100]), &bad)
		require.NoError(t, err)
		require.Empty(t, tail.headers)
	})
}
