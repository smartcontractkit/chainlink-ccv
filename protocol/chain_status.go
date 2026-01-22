package protocol

import (
	"time"
)

// BlockHeader represents blockchain block header metadata.
type BlockHeader struct {
	// Number is the block number of this block.
	// Critical: This is used when querying for MessageSent events.
	Number uint64

	// Hash is the block hash of this block.
	// NOTE: this is only used for re-org detection and finality violation detection.
	Hash Bytes32

	// ParentHash is the block hash of the parent of this block.
	// NOTE: this is only used for re-org detection and finality violation detection.
	ParentHash Bytes32

	// Timestamp of when this block was minted/mined.
	// NOTE: does not seem to be read.
	Timestamp time.Time
}

// ReorgType indicates the type of reorg detected.
type ReorgType int

const (
	// ReorgTypeNormal indicates a regular reorg within finalized boundaries.
	ReorgTypeNormal ReorgType = iota
	// ReorgTypeFinalityViolation indicates a finality violation (critical error).
	ReorgTypeFinalityViolation
)

// String returns the string representation of ReorgType.
func (r ReorgType) String() string {
	switch r {
	case ReorgTypeNormal:
		return "Normal"
	case ReorgTypeFinalityViolation:
		return "FinalityViolation"
	default:
		return "Unknown"
	}
}

// ChainStatus represents a reorg or finality violation event.
//
// ResetToBlock usage:
// - ReorgTypeNormal: Block number to reset to (common ancestor)
// - ReorgTypeFinalityViolation: Always 0 (no safe reset point - requires immediate stop).
type ChainStatus struct {
	Type         ReorgType
	ResetToBlock uint64 // Block number to reset to (0 for finality violations)
}

func (c ChainStatus) IsFinalityViolated() bool {
	return c.Type == ReorgTypeFinalityViolation
}
