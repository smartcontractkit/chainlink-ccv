package protocol

import (
	"fmt"
	"time"
)

// BlockHeader represents blockchain block header metadata.
type BlockHeader struct {
	Number     uint64
	Hash       Bytes32
	ParentHash Bytes32
	Timestamp  time.Time
}

// ChainTail stores an ordered slice of block headers from stable tip to latest tip.
type ChainTail struct {
	blocks []BlockHeader // ordered from oldest (stable) to newest (tip)
	// TODO: Add a map for O(1) lookups by number and hash over the blocks Slice
}

// NewChainTail creates a new ChainTail from a slice of block headers.
// It validates that the blocks form a contiguous chain (parent hashes match)
// and that there are no duplicates.
func NewChainTail(blocks []BlockHeader) (*ChainTail, error) {
	if len(blocks) == 0 {
		return nil, fmt.Errorf("chain tail cannot be empty")
	}

	// Check for contiguous parent hashes
	for i := 1; i < len(blocks); i++ {
		if blocks[i].ParentHash != blocks[i-1].Hash {
			return nil, fmt.Errorf("non-contiguous blocks at index %d: block %d parent hash %s does not match previous block %d hash %s",
				i, blocks[i].Number, blocks[i].ParentHash, blocks[i-1].Number, blocks[i-1].Hash)
		}
	}

	// Check for duplicate block numbers
	seen := make(map[uint64]bool)
	for i, block := range blocks {
		if seen[block.Number] {
			return nil, fmt.Errorf("duplicate block number %d at index %d", block.Number, i)
		}
		seen[block.Number] = true
	}

	return &ChainTail{blocks: blocks}, nil
}

// StableTip returns the oldest (finalized/stable) block header in the tail.
func (t *ChainTail) StableTip() BlockHeader {
	if len(t.blocks) == 0 {
		return BlockHeader{}
	}
	return t.blocks[0]
}

// Tip returns the newest (latest) block header in the tail.
func (t *ChainTail) Tip() BlockHeader {
	if len(t.blocks) == 0 {
		return BlockHeader{}
	}
	return t.blocks[len(t.blocks)-1]
}

// Contains checks if a block header exists in the tail (by number and hash).
func (t *ChainTail) Contains(block BlockHeader) bool {
	for _, b := range t.blocks {
		if b.Number == block.Number && b.Hash == block.Hash {
			return true
		}
	}
	return false
}

// BlockByNumber retrieves a block header by its block number.
// Returns nil if not found.
func (t *ChainTail) BlockByNumber(num uint64) *BlockHeader {
	for i := range t.blocks {
		if t.blocks[i].Number == num {
			return &t.blocks[i]
		}
	}
	return nil
}

// Len returns the number of blocks in the tail.
func (t *ChainTail) Len() int {
	return len(t.blocks)
}

// Blocks returns a copy of all blocks in the tail (ordered from oldest to newest).
func (t *ChainTail) Blocks() []BlockHeader {
	blocks := make([]BlockHeader, len(t.blocks))
	copy(blocks, t.blocks)
	return blocks
}

// ChainStatusReorg indicates a regular reorg was detected.
type ChainStatusReorg struct {
	NewTail             ChainTail
	CommonAncestorBlock uint64 // Block number of common ancestor for recovery
}

// ChainStatusFinalityViolated indicates a finality violation was detected (critical error).
type ChainStatusFinalityViolated struct {
	ViolatedBlock    BlockHeader // The finalized block that was reorged
	NewTail          ChainTail   // The new chain tail showing correct state
	SafeRestartBlock uint64      // Last known good block to restart from
}
