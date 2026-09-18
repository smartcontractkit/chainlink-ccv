package evm

import (
	"context"
	"fmt"
	"math/big"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// headerFetcher is the slice of SourceReader the tail needs, as an interface so the linkage
// logic is unit-testable without an RPC client.
type headerFetcher interface {
	GetBlocksHeaders(ctx context.Context, blockNumbers []*big.Int) (map[uint64]protocol.BlockHeader, error)
}

// chainTail caches the hash-linked headers from the finalized block up to the latest head.
// Because every stored header's ParentHash equals the stored header below it, one link check
// at the head proves the entire unfinalized range is unchanged and needs no log re-query.
type chainTail struct {
	mu      sync.Mutex
	headers []protocol.BlockHeader // ascending, contiguous, hash-linked; [0] is the anchor
	fetcher headerFetcher
	lggr    logger.Logger
}

func newChainTail(fetcher headerFetcher, lggr logger.Logger) (*chainTail, error) {
	if fetcher == nil {
		return nil, fmt.Errorf("fetcher cannot be nil")
	}
	if lggr == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}
	return &chainTail{fetcher: fetcher, lggr: lggr}, nil
}

// advance reconciles the tail against the newly observed heads and reports whether the
// unfinalized range may have changed. Every error path also reports changed, so a caller that
// only checks the bool still re-reads the range rather than trusting a stale cache.
func (t *chainTail) advance(ctx context.Context, latest, finalized *protocol.BlockHeader) (bool, error) {
	if latest == nil || finalized == nil {
		return true, fmt.Errorf("latest and finalized must be non-nil")
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if latest.Number < finalized.Number {
		return true, fmt.Errorf("latest block %d is below finalized %d", latest.Number, finalized.Number)
	}

	if len(t.headers) == 0 {
		return true, t.reseed(ctx, latest, finalized)
	}

	head := t.headers[len(t.headers)-1]

	// The head went backwards: a lagging or rotated RPC node, not necessarily a reorg. Keep the
	// tail when the height the two views share still agrees.
	if latest.Number < head.Number {
		if stored, ok := t.at(latest.Number); ok && stored.Hash == latest.Hash {
			t.prune(finalized)
			return false, nil
		}
		t.lggr.Warnw("Head moved backwards to a different hash, reseeding tail",
			"storedHead", head.Number, "latest", latest.Number, "latestHash", latest.Hash)
		return true, t.reseed(ctx, latest, finalized)
	}

	// Same height: either nothing moved, or the head block itself was replaced.
	if latest.Number == head.Number {
		if latest.Hash == head.Hash {
			t.prune(finalized)
			return false, nil
		}
		t.lggr.Warnw("Head hash changed at the same height, reseeding tail",
			"blockNumber", head.Number, "storedHash", head.Hash, "newHash", latest.Hash)
		return true, t.reseed(ctx, latest, finalized)
	}

	// Head moved forward: fetch the gap below it and check the whole run links onto the tail.
	var extension []protocol.BlockHeader
	if latest.Number > head.Number+1 {
		gap, err := t.fetchRange(ctx, head.Number+1, latest.Number-1)
		if err != nil {
			return true, err
		}
		extension = gap
	}
	extension = append(extension, *latest)

	if err := linksOnto(head, extension); err != nil {
		t.lggr.Warnw("Reorg detected in unfinalized range, reseeding tail",
			"storedHead", head.Number, "storedHash", head.Hash, "latest", latest.Number, "error", err)
		return true, t.reseed(ctx, latest, finalized)
	}

	t.headers = append(t.headers, extension...)
	t.prune(finalized)
	return false, nil
}

// reseed rebuilds the tail over [finalized, latest]. The caller must treat the range as
// changed, since a rebuilt tail vouches for nothing it held before. Requires mu.
func (t *chainTail) reseed(ctx context.Context, latest, finalized *protocol.BlockHeader) error {
	t.headers = nil

	rebuilt := []protocol.BlockHeader{*finalized}
	if latest.Number > finalized.Number {
		if latest.Number > finalized.Number+1 {
			mid, err := t.fetchRange(ctx, finalized.Number+1, latest.Number-1)
			if err != nil {
				return err
			}
			rebuilt = append(rebuilt, mid...)
		}
		rebuilt = append(rebuilt, *latest)
		if err := linksOnto(*finalized, rebuilt[1:]); err != nil {
			// Inconsistent reads across an RPC pool land here; the caller re-reads the full
			// range anyway, so the tail simply stays cold until reads agree.
			return fmt.Errorf("could not build a linked tail over [%d, %d]: %w",
				finalized.Number, latest.Number, err)
		}
	}

	t.headers = rebuilt
	t.lggr.Infow("Seeded unfinalized chain tail",
		"anchor", finalized.Number, "head", latest.Number, "blocks", len(rebuilt))
	return nil
}

// prune drops headers below the finalized anchor. A stored hash that disagrees with the
// finalized header is a finality violation, so the tail is dropped and logged here while
// alarming on it stays with the verifier's finality checker. Requires mu.
func (t *chainTail) prune(finalized *protocol.BlockHeader) {
	if stored, ok := t.at(finalized.Number); ok && stored.Hash != finalized.Hash {
		t.lggr.Errorw("Finalized block hash disagrees with the cached tail, dropping tail",
			"blockNumber", finalized.Number, "storedHash", stored.Hash, "finalizedHash", finalized.Hash)
		t.headers = nil
		return
	}
	if len(t.headers) == 0 || t.headers[0].Number >= finalized.Number {
		return
	}
	if idx := finalized.Number - t.headers[0].Number; idx < uint64(len(t.headers)) {
		t.headers = t.headers[idx:]
	}
}

// at returns the stored header at blockNum. Requires mu.
func (t *chainTail) at(blockNum uint64) (protocol.BlockHeader, bool) {
	if len(t.headers) == 0 || blockNum < t.headers[0].Number {
		return protocol.BlockHeader{}, false
	}
	idx := blockNum - t.headers[0].Number
	if idx >= uint64(len(t.headers)) {
		return protocol.BlockHeader{}, false
	}
	return t.headers[idx], true
}

// fetchRange fetches headers for [start, end] inclusive, in ascending order.
// GetBlocksHeaders skips failed batch elements, so a missing header is an error here.
func (t *chainTail) fetchRange(ctx context.Context, start, end uint64) ([]protocol.BlockHeader, error) {
	if start > end {
		return nil, fmt.Errorf("invalid header range [%d, %d]", start, end)
	}
	blockNumbers := make([]*big.Int, 0, end-start+1)
	for n := start; n <= end; n++ {
		blockNumbers = append(blockNumbers, new(big.Int).SetUint64(n))
	}
	headers, err := t.fetcher.GetBlocksHeaders(ctx, blockNumbers)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch headers [%d, %d]: %w", start, end, err)
	}
	out := make([]protocol.BlockHeader, 0, end-start+1)
	for n := start; n <= end; n++ {
		header, ok := headers[n]
		if !ok {
			return nil, fmt.Errorf("missing header for block %d in range [%d, %d]", n, start, end)
		}
		out = append(out, header)
	}
	return out, nil
}

// linksOnto verifies chain is contiguous, ascending, and hash-linked onto base.
func linksOnto(base protocol.BlockHeader, chain []protocol.BlockHeader) error {
	prev := base
	for _, header := range chain {
		if header.Number != prev.Number+1 {
			return fmt.Errorf("block %d does not follow %d", header.Number, prev.Number)
		}
		if header.ParentHash != prev.Hash {
			return fmt.Errorf("block %d parent %s does not match block %d hash %s",
				header.Number, header.ParentHash, prev.Number, prev.Hash)
		}
		prev = header
	}
	return nil
}
